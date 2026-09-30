#!/usr/bin/env python
# -*- coding: utf-8 -*-

from typing import Tuple, Any, Optional
from types import SimpleNamespace
import socket
import threading
import weakref
import queue
import time
import asyncio

from . import (ServerTransport, ClientTransport,
               NonBlockingClientTransport, TransportTimeout)

max_pkt_size = 4096


class ConnectionlessTcpClientTransport(ClientTransport):
    """A TCP client that dials afresh for every call.

    Nothing is held between calls, so there is no connection to go stale and
    nothing to reconnect: a client and a service can be restarted in any
    order.  That is the same bargain
    :py:class:`~tinyrpc.transports.http.HttpPostClientTransport` makes, which
    also opens a connection per request.

    :param packer: Framing.  The default is length-prefixed
        (:py:class:`TransportPackerRobust`); the server must use the same.
    """

    def __init__(self, endpoint: tuple[str, int],
                 packer: Any = None,
                 timeout: Any = None,
                 **kwargs: Any) -> None:
        self.endpoint = endpoint
        self.timeout = timeout
        if packer is None:
            packer = default_packer()
        self.packer = packer

    def send_message(self, message: bytes, expect_reply: bool = True,
                     timeout: Any = None) -> bytes:
        if timeout is None:
            timeout = self.timeout

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if timeout is not None:
                sock.settimeout(timeout)
            sock.connect(self.endpoint)

            self.packer.send(sock, message)
            if expect_reply:
                return self.packer.recv(sock)


class ConnectionlessTcpServerTransport(ServerTransport):
    """Server transport for clients that dial once per call.

    Accepting and reading happen on threads of their own, and completed
    messages are handed to the server loop through a queue.  Doing the read
    in :py:meth:`receive_message` instead -- as this used to -- serialises
    it with everything else the server is doing, so one slow client stalls
    every other.

    :param sock: A listening socket.
    :param packer: Framing.  The default is length-prefixed
        (:py:class:`TransportPackerRobust`), which the previous default was
        not: it read a single 4096-byte chunk, so a larger message arrived
        truncated and two smaller ones could arrive as one.
    :param poll_timeout: How long :py:meth:`receive_message` waits before
        raising :py:exc:`TransportTimeout`, which lets a server loop notice
        it has been asked to stop.
    :param read_timeout: How long a client has to finish sending, after
        which its connection is dropped.
    """

    def __init__(self, sock: Any,
                 packer: Any = None,
                 poll_timeout: float = 0.5,
                 read_timeout: float = 30.0,
                 logger: Any = None,
                 ) -> None:
        self.sock = sock
        if packer is None:
            packer = default_packer()
        self.packer = packer
        self.poll_timeout = poll_timeout
        self.read_timeout = read_timeout
        self.logger = logger

        self.messages = queue.Queue()
        self._ev_quit = threading.Event()
        self._thread = None
        # As for the HTTP transport: start() and stop() may be called from
        # more than one place, so both must tolerate it.
        self._lifecycle = threading.Lock()

    @property
    def endpoint(self) -> tuple:
        """The address actually bound, which is what to register with a name
        service when the port was chosen by the OS."""
        return self.sock.getsockname()[:2]

    def start(self) -> None:
        """Begin accepting connections, on a thread of its own."""
        with self._lifecycle:
            if self._thread is not None:
                return
            self._thread = threading.Thread(target=self._accept_forever,
                                            name='tcp-transport')
            self._thread.daemon = True
            self._thread.start()

    def stop(self) -> None:
        """Stop accepting and release the listening socket."""
        self._ev_quit.set()
        try:
            self.sock.close()
        except Exception:
            pass

        with self._lifecycle:
            thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=5.0)

    def _log(self, message: str) -> None:
        if self.logger is not None:
            self.logger.debug(message)

    def _accept_forever(self) -> None:
        self.sock.settimeout(0.5)
        while not self._ev_quit.is_set():
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                # The listening socket was closed, most likely by stop().
                break

            reader = threading.Thread(target=self._read_one, args=(conn, addr))
            reader.daemon = True
            reader.start()

    def _read_one(self, conn: socket.socket, addr: Tuple) -> None:
        """Read one message off a freshly accepted connection.

        Runs on its own thread, so a client that connects and then says
        nothing costs one thread until it times out rather than blocking the
        service.  Failures are dropped: a connection nobody can read from is
        not the server's problem to raise about.
        """
        try:
            conn.settimeout(self.read_timeout)
            message = self.packer.recv(conn)
        except Exception as e:
            self._log("dropping connection from %s: %s" % (addr, e))
            try:
                conn.close()
            except Exception:
                pass
            return

        context = SimpleNamespace(sock=conn, client_address=addr,
                                  # No credential channel: unlike HTTP there
                                  # is no header to carry one.
                                  auth=None)
        self.messages.put((context, message))

    def receive_message(self) -> Tuple[Any, bytes]:
        """Return the next ``(context, message)`` pair.

        :raises TransportTimeout: when nothing arrived within
            ``poll_timeout``.  Not an error: it lets a server loop test its
            termination flag between requests.
        """
        try:
            return self.messages.get(timeout=self.poll_timeout)
        except queue.Empty:
            raise TransportTimeout()

    def send_reply(self, context: Any, reply: bytes) -> None:
        with context.sock:
            self.packer.send(context.sock, reply)

    @classmethod
    def create(cls, endpoint: tuple[str, int], backlog: int = 64,
               packer: Any = None, **kwargs: Any
               ) -> 'ConnectionlessTcpServerTransport':
        """Create and bind a new server transport.

        :param endpoint: The endpoint clients will connect to.  Use port 0 to
            let the OS choose, then read :py:attr:`endpoint` back.
        :param backlog: Pending connections to allow.  The former default of
            0 leaves almost no room for a burst.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(endpoint)
        sock.listen(backlog)
        return cls(sock, packer=packer, **kwargs)


class TcpClientTransport(ClientTransport):
    """A client that connects once and then blocks on each call.

    The plain counterpart to :py:class:`TcpServerTransport`: one connection,
    one call at a time.  :py:class:`NonBlockingTcpClientTransport` is the
    same connection used by a multiplexing client, and reconnects when it
    drops; this one does neither, so it suits a caller that wants a socket
    and nothing clever.

    The transport interface is not designed for concurrent use, so each
    thread should make its own.

    :param endpoint: ``(host, port)`` to connect to.
    :param packer: Framing.  The default is length-prefixed
        (:py:class:`TransportPackerRobust`), which is what
        :py:class:`TcpServerTransport` expects.  Pass
        ``packer=TransportPacker()`` for a peer that is not ``tinyrpc``:
        standard msgpack-RPC over TCP has no length prefix.
    """

    def __init__(self,
                 endpoint: tuple[str, int],
                 packer: Any = None) -> None:
        self.endpoint = endpoint
        if packer is None:
            packer = default_packer()
        self.packer = packer
        self.connect()

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(self.endpoint)

    def send_message(self, message: bytes, expect_reply: bool = True,
                     timeout: Any = None) -> bytes:
        # RPCClient.call() passes whatever it was given straight through, so
        # a transport that does not take `timeout` turns client.call(...,
        # timeout=5) into a TypeError rather than a timeout.
        if timeout is not None:
            self.sock.settimeout(timeout)
        self.packer.send(self.sock, message)
        if expect_reply:
            try:
                recv_data = self.packer.recv(self.sock)
            except ConnectionError:
                recv_data = b''
            return recv_data

    def close(self) -> None:
        sock, self.sock = getattr(self, 'sock', None), None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


class TcpServerTransport(ServerTransport):
    """Server transport that keeps each client's connection open.

    The counterpart to :py:class:`NonBlockingTcpClientTransport`: a client
    connects once and sends many requests, which is what multiplexing needs.
    Contrast :py:class:`ConnectionlessTcpServerTransport`, which answers one
    request per connection and hangs up.

    Each connection gets a reader thread, and completed messages reach the
    server loop through a queue.  Replies are written straight back on the
    connection they came from, under a per-connection lock, so a reply does
    not have to wait for the server loop to come round again -- and two
    workers replying to the same client cannot interleave their bytes.

    :param sock: A listening socket.
    :param packer: Framing.  The default is length-prefixed
        (:py:class:`TransportPackerRobust`).  Framing is not optional here:
        with several requests in flight on one connection there is nothing
        else to say where one ends and the next begins.
    :param poll_timeout: How long :py:meth:`receive_message` waits before
        raising :py:exc:`TransportTimeout`, which lets a server loop notice
        it has been asked to stop.
    """

    def __init__(self,
                 sock: Any,
                 packer: Any = None,
                 poll_timeout: float = 0.5,
                 logger: Any = None) -> None:
        self.sock = sock
        if packer is None:
            packer = default_packer()
        self.packer = packer
        self.poll_timeout = poll_timeout
        self.logger = logger

        self.messages = queue.Queue()
        self._ev_quit = threading.Event()
        self._thread = None
        self._lifecycle = threading.Lock()

    @property
    def endpoint(self) -> tuple:
        return self.sock.getsockname()[:2]

    def _log(self, message: str) -> None:
        if self.logger is not None:
            self.logger.debug(message)

    def start(self) -> None:
        with self._lifecycle:
            if self._thread is not None:
                return
            self._thread = threading.Thread(target=self._accept_forever,
                                            name='tcp-server')
            self._thread.daemon = True
            self._thread.start()

    def stop(self) -> None:
        self._ev_quit.set()
        try:
            self.sock.close()
        except Exception:
            pass
        with self._lifecycle:
            thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=5.0)

    def _accept_forever(self) -> None:
        self.sock.settimeout(0.5)
        while not self._ev_quit.is_set():
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            reader = threading.Thread(target=self._serve_connection,
                                      args=(conn, addr))
            reader.daemon = True
            reader.start()

    def _serve_connection(self, conn: socket.socket, addr: Tuple) -> None:
        """Read requests off one connection for as long as it lasts."""
        context = SimpleNamespace(sock=conn, client_address=addr,
                                  send_lock=threading.Lock(),
                                  # A bare socket carries no credentials.
                                  auth=None)
        try:
            while not self._ev_quit.is_set():
                message = self.packer.recv(conn)
                if not message:
                    break
                self.messages.put((context, message))
        except Exception as e:
            self._log('connection from %s ended: %s' % (addr, e))
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def receive_message(self) -> Tuple[SimpleNamespace, bytes]:
        """Return the next ``(context, message)`` pair.

        :raises TransportTimeout: when nothing arrived within
            ``poll_timeout``.
        """
        try:
            return self.messages.get(timeout=self.poll_timeout)
        except queue.Empty:
            raise TransportTimeout()

    def send_reply(self, ctx: SimpleNamespace, reply: bytes) -> None:
        """Write a reply back on the connection it came from.

        The connection stays open: this client will send more.  A failure
        here means the client has gone, which is its business rather than
        ours, so it is logged rather than raised into the server loop.
        """
        try:
            with ctx.send_lock:
                self.packer.send(ctx.sock, reply)
        except Exception as e:
            self._log('could not reply to %s: %s' % (ctx.client_address, e))

    @classmethod
    def create(cls, endpoint: tuple[str, int], backlog: int = 64,
               packer: Any = None,
               **kwargs: Any) -> 'TcpServerTransport':
        """Create and bind a new server transport.

        :param endpoint: The endpoint clients will connect to.  Use port 0 to
            let the OS choose, then read :py:attr:`endpoint` back.
        :param backlog: Pending connections to allow.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(endpoint)
        sock.listen(backlog)
        return cls(sock, packer=packer, **kwargs)


class NonBlockingTcpClientTransport(NonBlockingClientTransport):
    """A TCP client transport that can send without waiting for the reply.

    Holds one connection open and multiplexes requests over it, so it pairs
    with :py:class:`~tinyrpc.client_multiplexing.MultiplexingRPCClient` and a
    protocol that carries a correlation id.  A reader thread owns the
    receiving end and puts whole messages on a queue; senders write under a
    lock.  Nothing else touches the socket, which is what makes it safe to
    use from several threads at once.

    Unlike a transport that dials per call, this one holds a connection that
    can die -- so it dials again.  Connecting is lazy and repeated: the first
    send opens the connection, and a send after a drop opens a new one, so a
    client and a service can still be started in either order and a service
    can be restarted underneath a client that outlives it.

    What cannot be recovered is a call that was already in flight when the
    connection went: its reply is gone.  Those surface as timeouts at the
    layer above, which is where the decision to retry belongs -- retrying
    here would silently repeat calls that are not necessarily idempotent.

    :param endpoint: ``(host, port)`` to connect to.
    :param packer: Framing.  The default is length-prefixed
        (:py:class:`TransportPackerRobust`).  Framing is not optional here:
        without a length prefix there is no way to tell where one reply ends
        and the next begins, and multiplexing depends on that.
    :param connect_timeout: Seconds to allow for establishing a connection.
    :param reconnect_interval: The shortest gap between connection attempts,
        so that a service that is down is not hammered.
    """

    def __init__(self,
                 endpoint: tuple[str, int],
                 packer: Any = None,
                 connect_timeout: float = 10.0,
                 reconnect_interval: float = 0.5,
                 logger: Any = None) -> None:
        self.endpoint = endpoint
        self.connect_timeout = connect_timeout
        self.reconnect_interval = reconnect_interval
        self.logger = logger
        if packer is None:
            packer = default_packer()
        self.packer = packer

        self.incoming = queue.Queue()
        self._lock = threading.RLock()
        self._sock = None
        self._reader = None
        self._generation = 0
        self._last_attempt = 0.0
        self._closed = False

    def _log(self, message: str) -> None:
        if self.logger is not None:
            self.logger.debug(message)

    @property
    def connected(self) -> bool:
        with self._lock:
            return self._sock is not None

    def connect(self) -> None:
        """Establish the connection now, rather than on the first send."""
        self._ensure_connection()

    def _ensure_connection(self) -> socket.socket:
        """Return a live socket, dialling if there is not one.

        :raises ConnectionError: if a connection cannot be established.
        """
        with self._lock:
            if self._closed:
                raise ConnectionError('transport is closed')
            if self._sock is not None:
                return self._sock

            # Do not dial faster than reconnect_interval, so that a service
            # which is down is asked politely rather than continuously.
            since = time.monotonic() - self._last_attempt
            if since < self.reconnect_interval:
                raise ConnectionError(
                    'not reconnecting to %s yet; last attempt %.2fs ago'
                    % (self.endpoint, since))
            self._last_attempt = time.monotonic()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.connect_timeout)
            try:
                sock.connect(self.endpoint)
            except OSError as e:
                try:
                    sock.close()
                except Exception:
                    pass
                raise ConnectionError('could not connect to %s: %s'
                                      % (self.endpoint, e)) from None

            # No timeout once connected: the reader blocks until a message
            # arrives, which may be a long time on a quiet connection.
            sock.settimeout(None)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            self._sock = sock
            self._generation += 1
            self._reader = threading.Thread(
                target=self._read_forever, args=(sock, self._generation),
                name='tcp-client-reader')
            self._reader.daemon = True
            self._reader.start()
            self._log('connected to %s' % (self.endpoint,))
            return sock

    @staticmethod
    def _hang_up(sock: socket.socket) -> None:
        """Close a connection whose reader may be blocked on it.

        close() alone is not enough: it releases the descriptor but does not
        interrupt a recv() already in progress on another thread, so the
        reader stays in the syscall and the thread is never reclaimed -- one
        leaked per drop, for the life of the process.  shutdown() is what
        wakes it, and it has to come first, because after close() there is no
        descriptor left to shut down.
        """
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass                # already dead at the far end, or never up
        try:
            sock.close()
        except Exception:
            pass

    def _drop(self, generation: int, why: Any) -> None:
        """Forget the current connection, if it is still the one named.

        The generation check keeps a reader that has just noticed a dead
        socket from tearing down the replacement somebody else has already
        put in its place.
        """
        with self._lock:
            if self._generation != generation or self._sock is None:
                return
            self._log('lost the connection to %s: %s' % (self.endpoint, why))
            self._hang_up(self._sock)
            self._sock = None

    def _read_forever(self, sock: socket.socket, generation: int) -> None:
        """Own the receiving end of one connection."""
        while True:
            try:
                message = self.packer.recv(sock)
            except Exception as e:
                self._drop(generation, e)
                return
            if not message:
                self._drop(generation, 'closed by the far end')
                return
            self.incoming.put(message)

    def send_message_noblock(self, message: bytes) -> None:
        """Send without waiting for the reply, connecting if need be."""
        with self._lock:
            sock = self._ensure_connection()
            generation = self._generation
            try:
                self.packer.send(sock, message)
            except Exception as e:
                self._drop(generation, e)
                raise ConnectionError('could not send to %s: %s'
                                      % (self.endpoint, e)) from None

    #: How often a waiter looks up from the queue to ask whether the
    #: connection it is waiting on is still there.  It does not delay a
    #: reply, which wakes the wait as soon as it arrives; it bounds only how
    #: long it takes to notice that none is coming.
    _liveness_check = 0.25

    def receive_reply(self, timeout: Any = None) -> bytes:
        """Return the next reply to arrive, from any outstanding request.

        :raises TimeoutError: when nothing arrived within ``timeout``.
        :raises ConnectionError: when the connection the request went out on
            died first.  Without this a caller that gave no timeout waits for
            a reply that provably cannot come -- which is what a held
            connection makes possible and a per-call one did not, since
            there the failure surfaced at connect time instead.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._lock:
            generation, alive = self._generation, self._sock is not None
        if not alive:
            raise ConnectionError('not connected to %s' % (self.endpoint,))

        while True:
            wait = self._liveness_check
            if deadline is not None:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError('no reply within %s seconds'
                                       % (timeout,))
                wait = min(wait, left)
            try:
                return self.incoming.get(block=True, timeout=wait)
            except queue.Empty:
                with self._lock:
                    gone = (self._sock is None
                            or self._generation != generation)
                if gone:
                    raise ConnectionError(
                        'the connection to %s went away while waiting for a '
                        'reply' % (self.endpoint,)) from None

    def send_message(self, message: bytes, expect_reply: bool = True,
                     timeout: Any = None) -> bytes:
        """Send and wait for a reply.

        Note that with several calls in flight this returns whichever reply
        arrives first, not necessarily the one for this message -- sorting
        them out is the job of a client that tracks correlation ids.
        """
        self.send_message_noblock(message)
        if expect_reply:
            return self.receive_reply(timeout=timeout)

    def close(self) -> None:
        """Close the connection and stop reconnecting."""
        with self._lock:
            self._closed = True
            if self._sock is not None:
                self._hang_up(self._sock)
                self._sock = None


class UnframedTcpClientTransport(NonBlockingTcpClientTransport):
    """A held TCP connection that sends messages with no length prefix.

    Which is what standard msgpack-RPC over TCP does: the msgpack stream is
    self-delimiting, so the body is the whole message and there is nothing
    to prefix it with.  Use this to talk to a peer that is not ``tinyrpc``.

    Everything else -- holding one connection, dialling again when it drops,
    the reader thread -- is :py:class:`NonBlockingTcpClientTransport`'s.
    Only the default packer differs, and that difference is on the wire: a
    peer expecting no prefix reads one as a malformed message and answers
    nothing, so the call does not fail, it times out.

    Prefer :py:class:`NonBlockingTcpClientTransport` between two ``tinyrpc``
    ends.  Its length prefix is what makes a reply larger than one read
    arrive whole -- without it a message that does not fit in a single
    ``recv()`` arrives in pieces -- and what a multiplexing client needs to
    tell replies apart.

    For a server that speaks the same unframed format, pass
    ``packer=TransportPacker()`` to
    :py:class:`TcpServerTransport` or
    :py:class:`ConnectionlessTcpServerTransport`.

    This was called ``AsyncTcpClientTransport``, which said what it is not:
    it is threaded, and has nothing to do with :py:mod:`asyncio` -- for that
    see :py:class:`AsyncioTcpClientTransport`.
    """

    def __init__(self, endpoint: tuple[str, int], packer: Any = None,
                 **kwargs: Any) -> None:
        super().__init__(endpoint,
                         packer=TransportPacker() if packer is None else packer,
                         **kwargs)


#: The former name.  A plain alias is safe here where it was not before:
#: it names the same class, so it carries the same framing.  What broke
#: last time was aliasing it to a class that framed differently.
#:
#: .. deprecated::
#:     Use :py:class:`UnframedTcpClientTransport`.
AsyncTcpClientTransport = UnframedTcpClientTransport


class TransportPacker:
    """This version of the transport packer does no size check and is
    limited to sending and receiving packets of `chunk_size`.
    """

    def __init__(self) -> None:
        self.version = b'1.0'
        self.chunk_size = 4096

    def pack(self, msg: bytes) -> bytes:
        return msg

    def send(self, sock: socket.socket, msg: bytes) -> None:
        try:
            sock.sendall(msg)
        except socket.error as e:
            raise ConnectionError(f"socket send error: {e}")

    def recv(self, sock: socket.socket) -> bytes:
        # read msg body from socket, fixed size
        try:
            msg = sock.recv(self.chunk_size)
        except socket.error as e:
            raise ConnectionError(f"socket recv error: {e}")
        num_recvd = len(msg)
        if num_recvd == 0:
            raise ConnectionError("no bytes received")
        return msg


class TransportPackerRobust(TransportPacker):
    """This version of the transport packer adds a header so that the
    size of the packet can be known and received more robustly.
    """

    def __init__(self) -> None:
        super().__init__()
        self.version = b'1.0'
        self.rpc_hdr_len = 32

    def pack(self, msg: bytes) -> bytes:
        hdr = b'%s,%d' % (
            self.version, len(msg))
        # pad header to required size
        hdr += b' ' * (self.rpc_hdr_len - len(hdr))
        if len(hdr) != self.rpc_hdr_len:
            raise ValueError("RPC header len actual(%d) != expected(%d)" % (
                len(hdr), self.rpc_hdr_len))
        return hdr + msg

    def send(self, sock: socket.socket, msg: bytes) -> None:
        try:
            sock.sendall(self.pack(msg))
        except socket.error as e:
            raise ConnectionError(f"socket send error: {e}")

    def recv(self, sock: socket.socket) -> bytes:
        # receive RPC header
        try:
            hdr = sock.recv(self.rpc_hdr_len, socket.MSG_WAITALL)
        except socket.error as e:
            raise ConnectionError(f"socket recv error: {e}")
        num_recvd = len(hdr)
        if num_recvd == 0:
            raise ConnectionError("no bytes received")
        if len(hdr) != self.rpc_hdr_len:
            raise ValueError("RPC header len actual(%d) != expected(%d)" % (
                len(hdr), self.rpc_hdr_len))

        # unpack RPC header
        tup = hdr.strip().split(b',')
        if len(tup) != 2:
            raise ValueError("RPC header: num fields(%d) != expected(%d) [hdr:%s]" % (
                len(tup), 2, hdr))
        ver, body_size = tup
        # TODO: version check
        body_size = int(body_size)

        # read msg body from socket, now that we know the size
        try:
            msg = sock.recv(body_size, socket.MSG_WAITALL)
        except socket.error as e:
            raise ConnectionError(f"socket recv error: {e}")
        if len(msg) < body_size:
            # we didn't receive all of the body--read the rest
            pieces = [ msg ]
            size_rem = body_size - len(msg)
            while size_rem > 0:
                pieces.append(sock.recv(size_rem))
                size_rem -= len(pieces[-1])
            msg = b''.join(pieces)

        return msg



class _MsgpackStream:
    """One connection's worth of half-read msgpack.

    The Unpacker is only used to find where each message ends: `tell()`
    reports how far into the stream it has consumed, so the bytes handed
    back are the ones that arrived, not a re-encoding of the object.  That
    keeps this a framing concern and leaves decoding to the protocol, which
    is the layer that knows what it asked for.
    """

    #: How many already-returned bytes to keep before trimming the buffer.
    #: Trimming is O(n) in what remains, so it is worth doing in batches.
    trim_at = 1 << 16

    def __init__(self, unpacker: Any) -> None:
        self.unpacker = unpacker
        self.buf = bytearray()
        # Stream offsets: `base` is the offset of buf[0], `consumed` is how
        # far messages have been handed out, `fed` how much has gone into the
        # Unpacker.  The Unpacker counts from the start of the stream and
        # knows nothing of the trimming, so all of these are kept in the same
        # units and differenced.
        self.base = 0
        self.consumed = 0
        self.fed = 0

    @property
    def drained(self) -> bool:
        """Whether every byte read so far has been handed out."""
        return self.consumed == self.fed

    def feed_whole(self, data: bytes) -> Optional[bytes]:
        """Feed a read that may be a message all by itself.

        The common case by far -- a small call arriving in one piece -- and
        worth not copying: when the buffer was drained and this read holds
        exactly one message, the read *is* the message and can be handed
        straight back.  Anything else falls through to the buffer.
        """
        self.unpacker.feed(data)
        self.fed += len(data)
        try:
            self.unpacker.unpack()
        except Exception as e:
            if type(e).__name__ != 'OutOfData':
                raise
            # Incomplete: the bytes have to be kept after all.
            self.buf += data
            return None

        if self.unpacker.tell() == self.fed:
            # Exactly one message, nothing left over.  buf stays empty, so
            # base moves with consumed to keep the offsets in step.
            self.consumed = self.fed
            self.base = self.fed
            return data

        # More than one message in this read: keep them and let
        # next_message() cut them up, rewinding what was just consumed.
        self.buf += data
        end = self.unpacker.tell()
        message = bytes(self.buf[self.consumed - self.base:end - self.base])
        self.consumed = end
        return message

    def feed(self, data: bytes) -> None:
        self.buf += data
        self.unpacker.feed(data)
        self.fed += len(data)

    def next_message(self) -> Optional[bytes]:
        """The next complete message, or None if more bytes are needed."""
        try:
            self.unpacker.unpack()
        except Exception as e:
            # OutOfData is the ordinary "not yet"; anything else is a stream
            # this packer cannot make sense of, and is the caller's to report.
            if type(e).__name__ != 'OutOfData':
                raise
            return None

        end = self.unpacker.tell()
        start = self.consumed
        message = bytes(self.buf[start - self.base:end - self.base])
        self.consumed = end

        if start - self.base > self.trim_at:
            del self.buf[:start - self.base]
            self.base = start
        return message


class TransportPackerMsgpack(TransportPacker):
    """Framing for standard msgpack-RPC: none on the wire.

    msgpack is self-delimiting, so a msgpack-RPC peer sends objects back to
    back with no length prefix.  :py:class:`TransportPacker` puts nothing on
    the wire either, which is why it interoperates -- but it hands the
    protocol whatever one ``recv()`` returned, so a message larger than a
    read arrives in pieces and two small ones that arrived together arrive
    as one.

    This reads the stream properly instead: bytes go into an Unpacker until
    a whole message is there, and what is left over stays for the next call.
    The bytes on the wire are identical to :py:class:`TransportPacker`'s --
    this is the same wire format, read correctly -- so it is the packer to
    give a peer that is not ``tinyrpc``.

    It is stateful per connection, and one packer instance serves every
    connection a server accepts, so the state is keyed by socket and held
    weakly: when a connection is closed and collected, its half-read bytes
    go with it.
    """

    def __init__(self, chunk_size: int = 65536) -> None:
        super().__init__()
        try:
            import msgpack
        except ImportError:
            raise ImportError(
                "TransportPackerMsgpack needs the 'msgpack' package, which "
                "is what makes a length prefix unnecessary")
        self._msgpack = msgpack
        self.chunk_size = chunk_size
        self._streams: Any = weakref.WeakKeyDictionary()
        self._lock = threading.Lock()

    def pack(self, msg: bytes) -> bytes:
        return msg

    def send(self, sock: socket.socket, msg: bytes) -> None:
        try:
            sock.sendall(msg)
        except socket.error as e:
            raise ConnectionError(f"socket send error: {e}")

    def _stream(self, sock: socket.socket) -> _MsgpackStream:
        with self._lock:
            stream = self._streams.get(sock)
            if stream is None:
                stream = _MsgpackStream(
                    self._msgpack.Unpacker(raw=False, strict_map_key=False))
                self._streams[sock] = stream
            return stream

    def recv(self, sock: socket.socket) -> bytes:
        stream = self._stream(sock)
        while True:
            message = stream.next_message()
            if message is not None:
                return message

            drained = stream.drained
            try:
                data = sock.recv(self.chunk_size)
            except socket.error as e:
                raise ConnectionError(f"socket recv error: {e}")
            if not data:
                raise ConnectionError("no bytes received")

            if drained:
                message = stream.feed_whole(data)
                if message is not None:
                    return message
            else:
                stream.feed(data)


def default_packer() -> TransportPacker:
    """The framing a threaded TCP transport uses when given no packer.

    One decision in one place, because it has to be the same at both ends of
    a connection and there is no way for either to find out what the other
    chose.  Seven ``__init__`` methods each naming a class independently is
    how a client and its server came to disagree once already: the server was
    moved to the length-prefixed packer and the client was left behind, and
    a framing mismatch does not raise -- it times out.

    Pass ``packer=TransportPacker()`` to both ends instead to speak the
    unframed wire format that standard msgpack-RPC over TCP uses.  That is
    supported on servers as well as clients; the limit is that a message
    larger than one read arrives in pieces, which is what the prefix exists
    to fix.
    """
    return TransportPackerRobust()


def default_asyncio_packer() -> 'AsyncioTransportPacker':
    """As :py:func:`default_packer`, for the asyncio transports."""
    return AsyncioTransportPackerRobust()


class AsyncioTcpClientTransport(ClientTransport):
    """An asyncio TCP client, holding its connection open.

    NOTE: (from the base class doc)
    Also note that the client transport interface is not designed for
    asynchronous use. This means each thread should make their own client.

    The connection is opened on the first send rather than in the
    constructor: ``connect()`` is a coroutine, and a constructor cannot await
    one -- it used to call it and drop the coroutine on the floor, which left
    the transport with no reader or writer and made it unusable.
    """

    def __init__(self,
                 endpoint: tuple[str, int],
                 packer: Any = None,
                 timeout: Any = None) -> None:
        self.endpoint = endpoint
        self.timeout = timeout
        if packer is None:
            packer = default_asyncio_packer()
        self.packer = packer
        self.reader = None
        self.writer = None

    async def connect(self) -> None:
        """Open the connection, if it is not open already."""
        if self.writer is not None:
            return
        host, port = self.endpoint
        self.reader, self.writer = await asyncio.open_connection(host, port)

    async def close(self) -> None:
        """Close the connection."""
        writer, self.writer, self.reader = self.writer, None, None
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def send_message(self, message: bytes,
                           expect_reply: bool = True,
                           timeout: Optional[float] = None) -> bytes:
        """Send a message and, unless told not to, wait for the reply.

        :param timeout: Seconds to wait for that reply.  Without one a peer
            that accepts the request and never answers leaves this awaiting
            forever; every other client transport here takes a bound, so
            this one does too.
        """
        await self.connect()
        await self.packer.send(self.writer, message)

        if expect_reply:
            try:
                if timeout is None:
                    recv_data = await self.packer.recv(self.reader)
                else:
                    recv_data = await asyncio.wait_for(
                        self.packer.recv(self.reader), timeout)
            except ConnectionError:
                recv_data = b''
            return recv_data


class AsyncioTcpServerTransport(ServerTransport):
    """An asyncio TCP server that keeps each client's connection open.

    A coroutine per connection reads requests off it and puts them on a
    queue; replies are written straight back on the connection they came
    from.  That mirrors :py:class:`TcpServerTransport`, so the threaded and
    asyncio servers behave the same way and speak the same framing.

    :param endpoint: ``(host, port)`` to bind.  A port of 0 asks the OS to
        choose, and :py:attr:`endpoint` is updated to what it chose, so a
        service can register the port it actually got.
    :param packer: Framing.  Length-prefixed by default.
    :param poll_timeout: How long :py:meth:`receive_message` waits before
        raising :py:exc:`TransportTimeout`, which lets a server loop notice
        it has been asked to stop.
    """

    def __init__(self,
                 endpoint: Any,
                 packer: Any = None,
                 poll_timeout: float = 0.5,
                 logger: Any = None) -> None:
        self.endpoint = endpoint
        self.poll_timeout = poll_timeout
        self.logger = logger
        self.incoming = asyncio.Queue()
        if packer is None:
            packer = default_asyncio_packer()
        self.packer = packer
        self._server = None

    def _log(self, message: str) -> None:
        if self.logger is not None:
            self.logger.debug(message)

    async def start(self) -> None:
        """Bind and serve until :py:meth:`stop` closes the listener."""
        if self._server is not None:
            return
        host, port = self.endpoint
        self._server = await asyncio.start_server(self._serve_connection,
                                                  host, port)
        # Report what was actually bound, so a port of 0 can be used.
        self.endpoint = self._server.sockets[0].getsockname()[:2]
        try:
            await self._server.serve_forever()
        except asyncio.CancelledError:
            pass

    async def stop(self) -> None:
        """Stop accepting connections and release the listening socket."""
        server, self._server = self._server, None
        if server is not None:
            server.close()
            try:
                await server.wait_closed()
            except Exception:
                pass

    async def _serve_connection(self, reader: asyncio.StreamReader,
                                writer: asyncio.StreamWriter) -> None:
        """Read requests off one connection for as long as it lasts."""
        peer = writer.get_extra_info('peername')
        ctx = SimpleNamespace(writer=writer, client_address=peer,
                              send_lock=asyncio.Lock(),
                              # A bare socket carries no credentials.
                              auth=None)
        try:
            while True:
                message = await self.packer.recv(reader)
                if not message:
                    break
                await self.incoming.put((ctx, message))
        except (ConnectionError, asyncio.IncompleteReadError) as e:
            self._log('connection from %s ended: %s' % (peer, e))
        finally:
            writer.close()

    async def receive_message(self) -> Tuple[SimpleNamespace, bytes]:
        """Return the next ``(context, message)`` pair.

        :raises TransportTimeout: when nothing arrived within
            ``poll_timeout``.
        """
        try:
            return await asyncio.wait_for(self.incoming.get(),
                                          timeout=self.poll_timeout)
        except asyncio.TimeoutError:
            raise TransportTimeout() from None

    async def send_reply(self, ctx: SimpleNamespace, reply: bytes) -> None:
        """Write a reply back on the connection it came from."""
        try:
            async with ctx.send_lock:
                await self.packer.send(ctx.writer, reply)
        except Exception as e:
            self._log('could not reply to %s: %s' % (ctx.client_address, e))

    @classmethod
    def create(cls, endpoint: tuple[str, int], backlog: int = 64,
               packer: Any = None,
               **kwargs: Any) -> 'AsyncioTcpServerTransport':
        """Create a new server transport.

        Note that it does not bind until :py:meth:`start` is awaited, since
        binding is itself a coroutine.

        :param endpoint: The endpoint clients will connect to.
        :param backlog: Accepted for symmetry with the other transports;
            asyncio manages the accept queue itself.
        """
        return cls(endpoint, packer=packer, **kwargs)


class AsyncioTransportPacker:
    """Unframed: reads one chunk of at most `chunk_size` bytes.

    .. warning::

        A message larger than a chunk arrives truncated, and two smaller ones
        can arrive as one, because nothing says where a message ends.  Prefer
        :py:class:`AsyncioTransportPackerRobust`, which both asyncio
        transports use by default.  This is kept for a peer that speaks the
        old unframed format.
    """

    def __init__(self) -> None:
        self.version = b'1.0'
        self.chunk_size = 4096

    def pack(self, msg: bytes) -> bytes:
        return msg

    async def send(self, writer: asyncio.StreamWriter,
                   msg: bytes) -> None:
        writer.write(msg)
        await writer.drain()

    async def recv(self, reader: asyncio.StreamReader) -> bytes:
        msg = await reader.read(self.chunk_size)
        if len(msg) == 0:
            raise ConnectionError("no bytes received")
        return msg


class AsyncioTransportPackerRobust(AsyncioTransportPacker):
    """Length-prefixed, so a message of any size arrives whole.

    The same framing as :py:class:`TransportPackerRobust`, so the asyncio and
    threaded transports are interchangeable on the wire.
    """

    def __init__(self) -> None:
        super().__init__()
        self.version = b'1.0'
        self.rpc_hdr_len = 32

    def pack(self, msg: bytes) -> bytes:
        hdr = b'%s,%d' % (self.version, len(msg))
        hdr += b' ' * (self.rpc_hdr_len - len(hdr))
        if len(hdr) != self.rpc_hdr_len:
            raise ValueError("RPC header len actual(%d) != expected(%d)" % (
                len(hdr), self.rpc_hdr_len))
        return hdr + msg

    async def send(self, writer: asyncio.StreamWriter,
                   msg: bytes) -> None:
        writer.write(self.pack(msg))
        await writer.drain()

    async def recv(self, reader: asyncio.StreamReader) -> bytes:
        try:
            hdr = await reader.readexactly(self.rpc_hdr_len)
        except asyncio.IncompleteReadError:
            raise ConnectionError("no bytes received") from None

        tup = hdr.strip().split(b',')
        if len(tup) != 2:
            raise ValueError(
                "RPC header: num fields(%d) != expected(%d) [hdr:%s]"
                % (len(tup), 2, hdr))
        _ver, body_size = tup

        try:
            return await reader.readexactly(int(body_size))
        except asyncio.IncompleteReadError:
            raise ConnectionError("truncated message body") from None
