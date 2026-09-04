#!/usr/bin/env python
# -*- coding: utf-8 -*-

from typing import Tuple, Any
from types import SimpleNamespace
import socket
import threading
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
                 **kwargs) -> None:
        self.endpoint = endpoint
        self.timeout = timeout
        if packer is None:
            packer = TransportPackerRobust()
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
            packer = TransportPackerRobust()
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
    """
    NOTE: (from the base class doc)
    Also note that the client transport interface is not designed for
    asynchronous use. This means each thread should make their own client.
    """

    def __init__(self,
                 endpoint: tuple[str, int],
                 packer: Any = None) -> None:
        self.endpoint = endpoint
        if packer is None:
            packer = TransportPacker()
        self.packer = packer
        self.connect()

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(self.endpoint)

    def send_message(self, message: bytes, expect_reply: bool =True) -> bytes:
        self.packer.send(self.sock, message)
        if expect_reply:
            try:
                recv_data = self.packer.recv(self.sock)
            except ConnectionError as e:
                recv_data = b''
            return recv_data


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
            packer = TransportPackerRobust()
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
            packer = TransportPackerRobust()
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
            try:
                self._sock.close()
            except Exception:
                pass
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

    def receive_reply(self, timeout: Any = None) -> bytes:
        """Return the next reply to arrive, from any outstanding request.

        :raises TimeoutError: when nothing arrived within ``timeout``.
        """
        try:
            return self.incoming.get(
                block=True, timeout=timeout if timeout is not None else None)
        except queue.Empty:
            raise TimeoutError('no reply within %s seconds' % (timeout,))

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
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None


#: Former name of :py:class:`NonBlockingTcpClientTransport`.  It was
#: misleading: this transport is threaded and has nothing to do with
#: :py:mod:`asyncio` (contrast :py:class:`AsyncioTcpClientTransport`).
#: TODO: remove once nothing refers to it.
AsyncTcpClientTransport = NonBlockingTcpClientTransport


class TransportPacker:
    """This version of the transport packer does no size check and is
    limited to sending and receiving packets of `chunk_size`.
    """

    def __init__(self):
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

    def __init__(self):
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


class AsyncioTcpClientTransport(ClientTransport):
    """
    NOTE: (from the base class doc)
    Also note that the client transport interface is not designed for
    asynchronous use. This means each thread should make their own client.
    """

    def __init__(self,
                 endpoint: tuple[str, int],
                 packer: Any = None,
                 timeout: Any = None) -> None:
        self.endpoint = endpoint
        self.timeout = timeout
        if packer is None:
            packer = AsyncioTransportPacker()
        self.packer = packer
        self.connect()

    async def connect(self) -> None:
        host, port = self.endpoint
        self.reader, self.writer = await asyncio.open_connection(host, port)

    async def send_message(self, message: bytes,
                           expect_reply: bool =True) -> bytes:
        await self.packer.send(self.writer, message)

        if expect_reply:
            try:
                recv_data = await self.packer.recv(self.reader)
            except ConnectionError as e:
                recv_data = b''
            return recv_data


class AsyncioTcpServerTransport(ServerTransport):
    def __init__(self,
                 endpoint: Any,
                 packer: Any = None,
                 timeout: float = 1.0) -> None:
        self.endpoint = endpoint
        self.timeout = timeout
        self.incoming = asyncio.Queue()
        if packer is None:
            packer = AsyncioTransportPacker()
        self.packer = packer

    async def start(self) -> None:
        host, port = self.endpoint
        while True:
            server = await asyncio.start_server(self._server, host, port)
            await server.serve_forever()

    async def _server(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        # create a Transport context to be passed around as needed
        ctx = SimpleNamespace(inbox=asyncio.Queue(), outbox=asyncio.Queue(),
                              ev_quit=asyncio.Event())
        t1 = asyncio.create_task(self._service_recv(reader, ctx))
        t2 = asyncio.create_task(self._service_send(writer, ctx))

        await t1
        await t2

    async def _service_recv(self, reader: asyncio.StreamReader,
                            ctx: SimpleNamespace) -> None:
        while not ctx.ev_quit.is_set():
            # service incoming
            try:
                recv_data = await self.packer.recv(reader)
            except ConnectionError:
                recv_data = b''
                ctx.ev_quit.set()

            if len(recv_data) > 0:
                await ctx.inbox.put(recv_data)
                await self.incoming.put(ctx)

    async def _service_send(self, writer: asyncio.StreamWriter,
                            ctx: SimpleNamespace) -> None:
        while not ctx.ev_quit.is_set():
            # service outgoing
            send_data = await ctx.outbox.get()
            await self.packer.send(writer, send_data)

    async def receive_message(self) -> Tuple[SimpleNamespace, bytes]:
        ctx = await self.incoming.get()
        msg = await ctx.inbox.get()
        return ctx, msg

    async def send_reply(self, ctx: SimpleNamespace, reply: bytes) -> None:
        await ctx.outbox.put(reply)

    @classmethod
    def create(cls, endpoint: tuple[str, int], backlog: int = 0) \
              -> 'AsyncioTcpServerTransport':
        """Create new server transport.

        Instead of creating the server yourself, you can call this function
        with the (host, port) endpoint.

        :param endpoint: The endpoint clients will connect to.
        :param backlog: The number of pending connections to allow.
        """
        return cls(endpoint)


class AsyncioTransportPacker:
    """This version of the transport packer does no size check and is
    limited to sending and receiving packets of `chunk_size`.
    """

    def __init__(self):
        self.version = b'1.0'
        self.chunk_size = 4096

    def pack(self, msg: bytes) -> bytes:
        return msg

    async def send(self, writer: asyncio.StreamWriter,
                   msg: bytes) -> None:
        #print("writer writing")
        writer.write(msg)
        await writer.drain()
        #print("writer wrote message")

    async def recv(self, reader: asyncio.StreamReader) -> bytes:
        # read msg body from socket, fixed size
        #print("reader reading")
        msg = await reader.read(n=self.chunk_size)
        num_recvd = len(msg)
        if num_recvd == 0:
            raise ConnectionError("no bytes received")
        #print(f"reader got message {num_recvd} bytes")
        return msg
