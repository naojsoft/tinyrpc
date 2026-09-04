#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""An HTTP client transport built on the standard library.

:py:class:`~tinyrpc.transports.http.HttpPostClientTransport` posts through
:py:mod:`requests`, whose per-request machinery -- building a session,
mounting adapters, preparing and hooking the request -- costs about a
millisecond before a byte moves.  On a small call that is most of the time
spent.  Measured on loopback, posting the same body:

    requests.post            1.44 ms
    httpx.Client.post        0.70 ms
    urllib3 PoolManager      0.55 ms
    http.client              0.40 ms
    hand-rolled over a raw socket
                             0.33 ms

So this uses :py:mod:`http.client`.  Hand-rolling the protocol is a further
18% on a small body and nothing at all on a large one, which is not worth
owning an HTTP implementation for -- particularly one that has to keep
talking to whatever XML-RPC peers are already out there.

Like the requests-based transport it dials for every call by default.  That
is what lets a client and a service be restarted in any order: there is no
held connection to go stale, so there is nothing to reconnect.
"""

import base64
import http.client
import socket
import ssl
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

from . import ClientTransport


class HttpClientTransport(ClientTransport):
    """POST a message over HTTP and return the response body.

    :param endpoint: The URL to post to.
    :param auth: ``(username, password)`` for HTTP Basic authentication, or
        ``None``.  Credentials in the URL are picked up as well, which is how
        Gen2 has always passed them.
    :param timeout: Seconds to allow for the whole exchange.
    :param verify: For ``https``, whether to check the server's certificate.
        Pass ``False`` for the self-signed certificates a private deployment
        typically uses.
    :param content_type: Sent with the request.  The server does not care --
        the protocol decides how to read the body -- but a proxy or a log
        reader might.
    """

    def __init__(
            self,
            endpoint: str,
            auth: Optional[Tuple[str, str]] = None,
            timeout: Any = None,
            verify: bool = True,
            content_type: str = 'application/octet-stream',
            **kwargs: Dict
    ) -> None:
        parts = urlsplit(endpoint)
        if parts.scheme not in ('http', 'https'):
            raise ValueError("unsupported scheme '%s'" % (parts.scheme,))

        self.endpoint = endpoint
        self.secure = parts.scheme == 'https'
        self.host = parts.hostname or '127.0.0.1'
        self.port = parts.port or (443 if self.secure else 80)
        self.path = parts.path or '/'
        self.timeout = timeout
        self.verify = verify
        self.content_type = content_type

        # Credentials given outright win over any in the URL.
        if auth is None and parts.username is not None:
            auth = (parts.username, parts.password or '')
        self.auth = tuple(auth) if auth is not None else None

        self._headers = {'Content-Type': content_type}
        if self.auth is not None:
            token = base64.b64encode(
                ('%s:%s' % self.auth).encode('utf-8')).decode('ascii')
            self._headers['Authorization'] = 'Basic ' + token

    def _connection(self):
        if not self.secure:
            return http.client.HTTPConnection(self.host, self.port,
                                              timeout=self.timeout)
        if self.verify:
            context = ssl.create_default_context()
        else:
            context = ssl._create_unverified_context()
        return http.client.HTTPSConnection(self.host, self.port,
                                           timeout=self.timeout,
                                           context=context)

    def send_message(self, message: bytes, expect_reply: bool = True,
                     timeout: Any = None) -> bytes:
        if not isinstance(message, bytes):
            raise TypeError('message must be of type bytes')

        conn = self._connection()
        if timeout is not None:
            conn.timeout = timeout
        try:
            headers = dict(self._headers)
            headers['Content-Length'] = str(len(message))
            conn.request('POST', self.path, body=message, headers=headers)
            response = conn.getresponse()
            body = response.read()

            if response.status != 200:
                # Not an RPC-level error -- those come back as a well-formed
                # reply with status 200 -- so something refused the request
                # before it reached the service.
                raise http.client.HTTPException(
                    'HTTP %d %s from %s' % (response.status, response.reason,
                                            self.endpoint))
            if expect_reply:
                return body
        except (socket.timeout, TimeoutError):
            # An OSError subclass, so a caller treating this as a failure of
            # the connection rather than of the call is right to.
            raise
        finally:
            try:
                conn.close()
            except Exception:
                pass
