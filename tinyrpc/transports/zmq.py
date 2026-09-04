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
        # Drained without asking whether it is readable, so it is never
        # allowed to block; see _serve_socket.
        self._wake_r.setblocking(False)
        self._ev_quit = threading.Event()
        self._thread = None
        self._shut = False
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
        """Close the socket and the wakeup pair, once.

        Both stop() and the socket thread's exit path want to do this, and
        closing a socketpair twice leaves the poller registered against a
        file descriptor of -1.
        """
        with self._lifecycle:
            if self._shut:
                return
            self._shut = True
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

                # Drain the wakeup unconditionally rather than asking the
                # poll whether it fired.  pyzmq reports a native socket by
                # its file descriptor rather than by the object registered,
                # so looking it up by object never matched -- and an
                # undrained pipe stays readable, which turned every poll
                # into an immediate return.  The resulting spin starved the
                # worker threads until one missed its deadline and a reply
                # was never produced: a request would arrive, and nothing
                # would answer it.
                while True:
                    try:
                        if not self._wake_r.recv(4096):
                            break
                    except (BlockingIOError, InterruptedError):
                        break
                    except OSError:
                        break

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
    """Client transport over a :py:const:`zmq.REQ` socket, held open.

    0mq expects peers to last.  A client that made a socket per call, dialled,
    sent and threw the socket away worked for a while and then began losing
    replies -- around three hundred calls in, with the server healthy and its
    queues empty -- because the router's idea of who its peers are cannot keep
    up with that much churn.  So the socket is kept.

    A 0mq socket must not be shared between threads, and a REQ socket also
    insists on strict send/receive alternation, so one is kept *per thread*
    rather than one per transport.  A thread therefore reuses its socket for
    every call it makes, and threads never contend.  This is what lets a
    single transport object be shared, which is how Gen2 uses a client.

    If a socket is left in a bad state by a failed exchange it is discarded
    and the next call on that thread dials again, which is the closest thing
    0mq has to the reconnection a stream transport needs.

    :param socket_factory: Called with no arguments to make a connected REQ
        socket for the calling thread.
    :param timeout: Seconds to wait for a reply.
    """

    def __init__(self, socket_factory, timeout: float = None) -> None:
        self._make_socket = socket_factory
        self.timeout = timeout
        self._local = threading.local()
        self._all = []
        self._lock = threading.Lock()

    def _socket(self):
        sock = getattr(self._local, 'socket', None)
        if sock is None:
            sock = self._make_socket()
            self._local.socket = sock
            with self._lock:
                self._all.append(sock)
        return sock

    def _discard(self):
        """Throw this thread's socket away, so the next call dials again.

        A REQ socket that did not complete its send/receive pair cannot be
        reused: it would refuse the next send.  Rather than track how far
        through the exchange we got, the socket is replaced.
        """
        sock = getattr(self._local, 'socket', None)
        self._local.socket = None
        if sock is None:
            return
        with self._lock:
            try:
                self._all.remove(sock)
            except ValueError:
                pass
        try:
            sock.close(linger=0)
        except Exception:
            pass

    def send_message(self, message: bytes, expect_reply: bool = True,
                     timeout: Any = None) -> bytes:
        if timeout is None:
            timeout = self.timeout

        sock = self._socket()
        try:
            sock.send(message)
        except Exception:
            self._discard()
            raise

        # 0mq's REQ will not send again until this reply is taken, so it is
        # always read, whether or not the caller wants it.
        try:
            if timeout is None:
                reply = sock.recv()
            else:
                if not sock.poll(int(timeout * 1000), zmq.POLLIN):
                    self._discard()
                    raise exc.TimeoutError()
                reply = sock.recv()
        except exc.TimeoutError:
            raise
        except Exception:
            self._discard()
            raise

        if expect_reply:
            return reply

    def close(self) -> None:
        """Close every socket this transport has handed out."""
        with self._lock:
            sockets, self._all = self._all, []
        for sock in sockets:
            try:
                sock.close(linger=0)
            except Exception:
                pass
        self._local = threading.local()

    @classmethod
    def create(cls, zmq_context: zmq.Context, endpoint: str,
               timeout: float = None) -> 'ZmqClientTransport':
        """Create a client transport for _endpoint_.

        The socket itself is made when a thread first makes a call, since it
        belongs to that thread.

        :param zmq_context: A 0mq context.
        :param endpoint: The endpoint the server is bound to.
        :param timeout: Seconds to wait for a reply.
        """
        def factory():
            sock = zmq_context.socket(zmq.REQ)
            sock.setsockopt(zmq.LINGER, 0)
            sock.connect(endpoint)
            return sock

        return cls(factory, timeout)
