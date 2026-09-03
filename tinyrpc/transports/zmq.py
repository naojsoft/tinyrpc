#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import  # needed for zmq import

from typing import Tuple, Any, Dict

import threading
import time

import zmq

from . import ServerTransport, ClientTransport, TransportTimeout
from .. import exc


class ZmqServerTransport(ServerTransport):
    """Server transport based on a :py:const:`zmq.ROUTER` socket.

    :param socket: A :py:const:`zmq.ROUTER` socket instance, bound to an
                   endpoint.
    """

    #: How long a single poll waits before the lock is released so that
    #: anything else wanting the socket can have a turn.
    POLL_SLICE_MS = 50

    def __init__(self, socket: zmq.Socket,
                 poll_timeout: float = 0.5) -> None:
        self.socket = socket
        self.poll_timeout = poll_timeout
        self.endpoint = None

        # A 0mq socket must not be touched by two threads at once, and three
        # of them want this one: the server loop polling and receiving, the
        # worker threads sending replies, and whoever calls stop().  Using it
        # unguarded does not merely interleave badly -- it segfaults.
        self._lock = threading.RLock()
        self._closed = False

    def start(self) -> None:
        """Nothing to start: the socket is already bound and listening."""

    def stop(self) -> None:
        """Close the socket.

        Taken under the same lock as everything else, so this waits for a
        poll or a send in progress rather than pulling the socket out from
        under it.
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self.socket.close(linger=0)
            except Exception:
                pass

    def receive_message(self) -> Tuple[Any, bytes]:
        """Return the next ``(context, message)`` pair.

        :raises TransportTimeout: when nothing arrived within
            ``poll_timeout``.  Without this the server loop would sit in
            ``recv_multipart`` and not notice it had been asked to stop until
            the next request happened to arrive.

        The wait is made of short slices rather than one long poll, so that a
        worker with a reply to send is not kept waiting for the socket for
        the whole interval.
        """
        deadline = None
        if self.poll_timeout is not None:
            deadline = time.monotonic() + self.poll_timeout

        while True:
            with self._lock:
                if self._closed:
                    raise TransportTimeout()

                remaining_ms = self.POLL_SLICE_MS
                if deadline is not None:
                    left = (deadline - time.monotonic()) * 1000
                    if left <= 0:
                        raise TransportTimeout()
                    remaining_ms = min(self.POLL_SLICE_MS, int(left) or 1)

                if self.socket.poll(remaining_ms, zmq.POLLIN):
                    msg = self.socket.recv_multipart()
                    return msg[:-1], msg[-1]

            if deadline is None:
                continue

    def send_reply(self, context: Any, reply: bytes) -> None:
        with self._lock:
            if self._closed:
                return
            self.socket.send_multipart(context + [reply])

    @classmethod
    def create(cls, zmq_context: zmq.Context, endpoint: str,
               poll_timeout: float = 0.5) -> 'ZmqServerTransport':
        """Create new server transport.

        Instead of creating the socket yourself, you can call this function and
        merely pass the :py:class:`zmq.core.context.Context` instance.

        By passing a context imported from :py:mod:`zmq.green`, you can use
        green (gevent) 0mq sockets as well.

        :param zmq_context: A 0mq context.
        :param endpoint: The endpoint clients will connect to.  A port of 0
            asks the OS to choose one, which is then readable back from
            :py:attr:`endpoint`.
        """
        socket = zmq_context.socket(zmq.ROUTER)
        transport = cls(socket, poll_timeout=poll_timeout)

        if endpoint.endswith(':0'):
            base = endpoint.rsplit(':', 1)[0]
            port = socket.bind_to_random_port(base)
            transport.endpoint = '%s:%d' % (base, port)
        else:
            socket.bind(endpoint)
            transport.endpoint = endpoint

        return transport


class ZmqClientTransport(ClientTransport):
    """Client transport based on a :py:const:`zmq.REQ` socket.

    :param socket: A :py:const:`zmq.REQ` socket instance, connected to the
                   server socket.
    :param timeout: An optional float. When set it defines the time period
                    in seconds to wait for a reply.
                    It will generate a :py:class:`exc.TimeoutError` exception
                    if no reply was received in time.
    """

    def __init__(self, socket: zmq.Socket, timeout: float = None) -> None:
        self.socket = socket
        self.timeout = timeout

    def close(self) -> None:
        """Release the socket.

        A caller that builds a transport per call -- which is how a
        connectionless client works -- would otherwise leave a socket behind
        each time, to be closed whenever the garbage collector got to it.
        """
        try:
            self.socket.close(linger=0)
        except Exception:
            pass

    def send_message(self, message: bytes, expect_reply: bool = True) -> bytes:
        self.socket.send(message)

        # zmq contains a state machine preventing a new request
        # until the previous one is answered, so always receive
        if self.timeout is None:
            reply = self.socket.recv()
        else:
            poller = zmq.Poller()
            poller.register(self.socket, zmq.POLLIN)
            ready = dict(poller.poll(int(self.timeout * 1000)))
            if ready.get(self.socket) == zmq.POLLIN:
                reply = self.socket.recv()
            else:
                raise exc.TimeoutError()
        if expect_reply:
            return reply

    @classmethod
    def create(cls, zmq_context: zmq.Context, endpoint: str, timeout: float = None) -> 'ZmqClientTransport':
        """Create new client transport.

        Instead of creating the socket yourself, you can call this function and
        merely pass the :py:class:`zmq.core.context.Context` instance.

        By passing a context imported from :py:mod:`zmq.green`, you can use
        green (gevent) 0mq sockets as well.

        :param zmq_context: A 0mq context.
        :param endpoint: The endpoint the server is bound to.
        :param timeout: Optional period in seconds to wait for reply
        """
        socket = zmq_context.socket(zmq.REQ)
        socket.connect(endpoint)
        return cls(socket, timeout)
