#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import  # needed for zmq import

from typing import Tuple, Any, Dict

import queue as _queue
import socket as _socket
import threading

import zmq

from . import ServerTransport, ClientTransport, TransportTimeout
from .. import exc


class ZmqServerTransport(ServerTransport):
    """Server transport based on a :py:const:`zmq.ROUTER` socket.

    :param socket: A :py:const:`zmq.ROUTER` socket instance, bound to an
                   endpoint.
    """

    def __init__(self, socket: zmq.Socket,
                 poll_timeout: float = 0.5) -> None:
        self.socket = socket
        self.poll_timeout = poll_timeout
        self.endpoint = None

        # A 0mq socket must not be touched by more than one thread, and three
        # would like to: the server loop receiving, the worker threads
        # replying, and whoever calls stop().  Rather than serialise them --
        # which works but lets the receive loop starve the senders, since it
        # reacquires the moment it lets go -- one thread owns the socket and
        # the others hand it work.
        #
        # A socketpair is the wakeup: it has a file descriptor, so the same
        # poll can wait on it and on the 0mq socket at once, and writing to
        # it from another thread is safe.  That means no busy polling and no
        # added latency on a reply.
        self._incoming = _queue.Queue()
        self._outgoing = _queue.Queue()
        self._wake_r, self._wake_w = _socket.socketpair()
        self._ev_quit = threading.Event()
        self._thread = None
        self._lifecycle = threading.Lock()

    def start(self) -> None:
        """Start the thread that owns the socket."""
        with self._lifecycle:
            if self._thread is not None:
                return
            self._thread = threading.Thread(target=self._serve_socket,
                                            name='zmq-transport')
            self._thread.daemon = True
            self._thread.start()

    def stop(self) -> None:
        """Ask the socket thread to finish, and wait for it to close up."""
        self._ev_quit.set()
        try:
            self._wake_w.send(b'\x01')
        except Exception:
            pass

        with self._lifecycle:
            thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=5.0)
        else:
            # Never started, so nobody else will close the socket.
            self._close()

    def _close(self):
        for handle in (self.socket, self._wake_r, self._wake_w):
            try:
                handle.close()
            except Exception:
                pass

    def _serve_socket(self):
        """Own the socket: receive requests, and send the replies queued."""
        poller = zmq.Poller()
        poller.register(self.socket, zmq.POLLIN)
        poller.register(self._wake_r, zmq.POLLIN)
        try:
            while not self._ev_quit.is_set():
                events = dict(poller.poll(500))

                if events.get(self._wake_r):
                    try:
                        self._wake_r.recv(4096)
                    except Exception:
                        pass

                while True:
                    try:
                        context, reply = self._outgoing.get_nowait()
                    except _queue.Empty:
                        break
                    try:
                        self.socket.send_multipart(context + [reply])
                    except Exception:
                        pass

                if events.get(self.socket) == zmq.POLLIN:
                    try:
                        msg = self.socket.recv_multipart()
                    except Exception:
                        break
                    self._incoming.put((msg[:-1], msg[-1]))
        finally:
            self._close()

    def receive_message(self) -> Tuple[Any, bytes]:
        """Return the next ``(context, message)`` pair.

        :raises TransportTimeout: when nothing arrived within
            ``poll_timeout``.  Without this the server loop would sit waiting
            and not notice it had been asked to stop until the next request
            happened to arrive.
        """
        if self._thread is None and not self._ev_quit.is_set():
            self.start()
        try:
            return self._incoming.get(timeout=self.poll_timeout)
        except _queue.Empty:
            raise TransportTimeout()

    def send_reply(self, context: Any, reply: bytes) -> None:
        """Hand a reply to the thread that owns the socket."""
        self._outgoing.put((context, reply))
        try:
            self._wake_w.send(b'\x01')
        except Exception:
            pass

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
