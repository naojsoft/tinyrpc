#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""HTTP server transport built on the standard library's :py:mod:`http.server`.

This is the server-side counterpart to
:py:class:`~tinyrpc.transports.http.HttpPostClientTransport`, for use where
pulling in a WSGI container (and therefore :py:mod:`werkzeug` plus a server
such as :py:mod:`gevent`) is not wanted.  It differs from
:py:class:`~tinyrpc.transports.wsgi.WsgiServerTransport` in two ways that
matter to callers:

* it is a *server*, not a WSGI application, so it needs no container, and
* the context it hands to :py:meth:`receive_message` carries the requesting
  client's address and any HTTP ``Authorization`` credentials, so that a
  server can authenticate and authorise a request without the protocol or
  the dispatcher having to know how the message arrived.

Like the WSGI transport, it hands each request off to the server loop through
a queue and blocks the HTTP handler thread until a reply arrives, so it must
be driven by a server running in another thread.
"""

import base64
import queue as _queue
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from typing import Any, Optional, Tuple

from . import ServerTransport, TransportTimeout

#: Requests larger than this are refused with ``413``.  The default is
#: deliberately generous: Gen2 pushes base64-encoded, compressed image and
#: header buffers through ordinary RPC calls.
DEFAULT_MAX_CONTENT_LENGTH = 256 * 1024 * 1024


class HttpServerTransportTimeout(TransportTimeout):
    """Raised when no request arrived within the transport's poll interval."""


def parse_basic_auth(header: Optional[str]) -> Optional[Tuple[str, str]]:
    """Decode an HTTP ``Authorization`` header holding Basic credentials.

    :param header: The raw header value, or ``None``.
    :return: A ``(username, password)`` tuple, or ``None`` when the header is
        absent, not Basic, or malformed.
    """
    if not header:
        return None
    try:
        method, _, encoded = header.partition(' ')
        if method.lower() != 'basic':
            return None
        decoded = base64.b64decode(encoded.strip().encode()).decode('utf-8')
        username, sep, password = decoded.partition(':')
        if not sep:
            return None
        return (username, password)
    except Exception:
        # A malformed header is indistinguishable, to us, from no header at
        # all; let the authenticator decide what to do about missing creds.
        return None


class _RPCRequestHandler(BaseHTTPRequestHandler):
    """Turns one HTTP POST into one message on the transport's queue."""

    # HTTP/1.1 is needed for the client to honour Content-Length reliably.
    # Whether the connection is then reused is decided per-response by the
    # transport's ``keep_alive`` setting.
    protocol_version = 'HTTP/1.1'

    # The handler writes headers and body as separate sends, so with Nagle on
    # a reused connection the second waits for the first to be acknowledged
    # -- and the peer's delayed ACK does not arrive for 40ms.  That turns a
    # 1.4ms call into a 44ms one.  Closing the connection hides it, which is
    # why it only appears once connections are kept alive.
    disable_nagle_algorithm = True

    # Filled in by the transport when it builds the server.
    transport = None

    def do_POST(self):
        transport = self.transport

        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except (TypeError, ValueError):
            self.send_error(400, 'Bad Content-Length')
            return

        if content_length <= 0:
            self.send_error(400, 'Empty request body')
            return

        if content_length > transport.max_content_length:
            self.send_error(413, 'Request body too large')
            return

        body = self.rfile.read(content_length)
        if len(body) != content_length:
            self.send_error(400, 'Truncated request body')
            return

        # The reply channel is per-request; the rest of the context is what a
        # server needs in order to decide whether to honour the request.
        context = SimpleNamespace(
            reply_queue=_queue.Queue(),
            client_address=self.client_address,
            auth=parse_basic_auth(self.headers.get('Authorization')),
            headers=self.headers,
            path=self.path,
        )

        transport.messages.put((context, body))

        try:
            reply = context.reply_queue.get(timeout=transport.reply_timeout)
        except _queue.Empty:
            self.send_error(504, 'Timed out waiting for the RPC server')
            return

        if reply is None:
            # A one-way request: the server chose not to answer.  HTTP still
            # requires a response, so send an empty one.
            reply = b''

        self.send_response(200)
        self.send_header('Content-Type', transport.content_type)
        self.send_header('Content-Length', str(len(reply)))
        if not transport.keep_alive:
            self.send_header('Connection', 'close')
            self.close_connection = True
        self.end_headers()
        self.wfile.write(reply)

    def do_GET(self):
        self.send_error(405, 'Only POST is supported')

    def log_message(self, fmt, *args):
        logger = getattr(self.transport, 'logger', None)
        if logger is not None:
            logger.debug("%s - %s" % (self.address_string(), fmt % args))


class HttpServerTransport(ServerTransport):
    """Server transport over :py:class:`http.server.ThreadingHTTPServer`.

    :param endpoint: The ``(host, port)`` to bind to.  Use port ``0`` to let
        the OS choose one; read it back from :py:attr:`endpoint` afterwards.
    :param content_type: The ``Content-Type`` sent with each reply.  Defaults
        to ``text/xml`` for XML-RPC; use ``application/json`` for JSON-RPC.
    :param keep_alive: When false (the default) every response carries
        ``Connection: close``, so each call gets its own TCP connection.  This
        matches the behaviour Gen2's XML-RPC services have always had.
    :param max_content_length: Requests with a larger body are refused.
    :param reply_timeout: How long an HTTP handler thread waits for the RPC
        server to produce a reply before giving up with ``504``.
    :param poll_timeout: How long :py:meth:`receive_message` blocks before
        raising :py:exc:`HttpServerTransportTimeout`, which gives a server
        loop the chance to notice that it should exit.
    :param ssl_context: An optional :py:class:`ssl.SSLContext`.  When given,
        the listening socket is wrapped and the service speaks HTTPS.
    :param logger: Optional logger for HTTP-level messages.
    """

    def __init__(
            self,
            endpoint: Tuple[str, int],
            content_type: str = 'text/xml',
            keep_alive: bool = False,
            max_content_length: int = DEFAULT_MAX_CONTENT_LENGTH,
            reply_timeout: float = 300.0,
            poll_timeout: float = 0.5,
            ssl_context: Optional[ssl.SSLContext] = None,
            logger: Any = None,
    ) -> None:
        self.content_type = content_type
        self.keep_alive = keep_alive
        self.max_content_length = max_content_length
        self.reply_timeout = reply_timeout
        self.poll_timeout = poll_timeout
        self.logger = logger

        self.messages = _queue.Queue()

        handler = type('_BoundRPCRequestHandler', (_RPCRequestHandler,),
                       {'transport': self})

        class _Server(ThreadingHTTPServer):
            daemon_threads = True
            # Let a service restart without waiting out TIME_WAIT.
            allow_reuse_address = True
            # The stdlib default of 5 is far too small for a busy service.
            request_queue_size = 64

        self.httpd = _Server(endpoint, handler)

        if ssl_context is not None:
            self.httpd.socket = ssl_context.wrap_socket(self.httpd.socket,
                                                        server_side=True)

        self._thread = None
        # start() and stop() are called from more than one place -- a server
        # loop's shutdown path and its owner's -- so both must be safe to
        # call twice and at once.
        self._lifecycle = threading.Lock()

    @property
    def endpoint(self) -> Tuple[str, int]:
        """The address actually bound, which is what to register with a name
        service when the port was chosen by the OS."""
        return self.httpd.server_address[:2]

    def start(self) -> None:
        """Begin accepting connections, in a thread of its own."""
        with self._lifecycle:
            if self._thread is not None:
                return
            self._thread = threading.Thread(target=self.httpd.serve_forever,
                                            name='http-transport')
            self._thread.daemon = True
            self._thread.start()

    def stop(self) -> None:
        """Stop accepting connections and release the listening socket.

        Safe to call whether or not :py:meth:`start` was.  ``shutdown()``
        waits for the serve loop to acknowledge, so calling it when that loop
        was never started waits for an acknowledgement that cannot come.
        """
        with self._lifecycle:
            thread, self._thread = self._thread, None

        if thread is not None:
            self.httpd.shutdown()
            thread.join(timeout=5.0)
        try:
            self.httpd.server_close()
        except Exception:
            pass

    def receive_message(self) -> Tuple[Any, bytes]:
        """Return the next ``(context, message)`` pair.

        :raises HttpServerTransportTimeout: when nothing arrived within
            ``poll_timeout``.  This is not an error; it exists so that a
            server loop can test its termination flag between requests.
        """
        try:
            return self.messages.get(timeout=self.poll_timeout)
        except _queue.Empty:
            raise HttpServerTransportTimeout()

    def send_reply(self, context: Any, reply: bytes) -> None:
        """Hand ``reply`` back to the HTTP thread waiting on ``context``."""
        context.reply_queue.put(reply)
