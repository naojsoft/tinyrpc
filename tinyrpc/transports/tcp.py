#!/usr/bin/env python
# -*- coding: utf-8 -*-

from typing import Tuple, Any
from types import SimpleNamespace
from collections import deque
import contextlib
import socket
import selectors
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

    def _log(self, message):
        if self.logger is not None:
            self.logger.debug(message)

    def _accept_forever(self):
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

    def _read_one(self, conn, addr):
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
               packer: Any = None, **kwargs
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

    def connect(self):
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
    """Server transport based on a :py:const:`socket` socket.

    :param socket: A :py:const:`socket` socket instance, bound to an
                   endpoint.
    """

    def __init__(self,
                 sock: Any,
                 packer: Any = None,
                 timeout: float = 1.0) -> None:
        self.sock = sock
        self.sock.setblocking(False)
        self.timeout = timeout
        self.sel = selectors.DefaultSelector()
        self.sel.register(self.sock, selectors.EVENT_READ, data=None)
        self.incoming = deque()
        self.lock = threading.RLock()
        if packer is None:
            packer = TransportPacker()
        self.packer = packer

    def _accept_connection(self):
        """This method is called when a client attempts to connect
        on our listening socket.
        """
        try:
            conn_sock, addr = self.sock.accept()
        except socket.error as e:
            # TODO: troubleshooting here? Re-establish listening socket?
            return
        #conn_sock.setblocking(False)
        # create a Transport context to be passed around as needed
        ctx = SimpleNamespace(sock=conn_sock, addr=addr,
                              inbox=deque(), outbox=deque(),
                              packer=self.packer)
        # we are interested in read/write events on the socket
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self.sel.register(conn_sock, events, data=ctx)

    def _service_read(self, sock, ctx):
        """This method is called when activity happens on a client-
        connected socket.
        """
        # service incoming
        try:
            recv_data = ctx.packer.recv(sock)
        except ConnectionError as e:
            recv_data = b''
        if len(recv_data) > 0:
            ctx.inbox.append(recv_data)
            self.incoming.append(ctx)
        else:
            # socket appears to be closed at other end
            try:
                self.sel.unregister(sock)
            except (KeyError, ValueError):
                # raises KeyError if socket is not registered
                pass
            #ctx.sock = None
            try:
                sock.close()
            except Exception:
                pass

    def _service_write(self, sock, ctx):
        # service outgoing
        buf = ctx.outbox.popleft()
        try:
            ctx.packer.send(sock, buf)
        except ConnectionError as e:
            # socket appears to be closed at other end
            # try to reconnect and send on another socket
            ctx.outbox.appendleft(buf)
            try:
                self.sel.unregister(sock)
            except (KeyError, ValueError):
                # raises KeyError if socket is not registered
                pass
            #ctx.sock = None
            try:
                sock.close()
            except Exception:
                pass

    def _process_events(self):
        try:
            with self.lock:
                events = self.sel.select(timeout=self.timeout)
                out_events = []
                # process all reads
                for key, mask in events:
                    if key.data is None:
                        # event on our listening socket
                        self._accept_connection()
                    else:
                        # event on an accepted socket
                        if mask & selectors.EVENT_READ:
                            sock, ctx = key.fileobj, key.data
                            self._service_read(sock, ctx)
                        if mask & selectors.EVENT_WRITE:
                            out_events.append(key)

                # process all pending writes
                for key in out_events:
                    sock, ctx = key.fileobj, key.data
                    if len(ctx.outbox) > 0:
                        self._service_write(sock, ctx)

        except Exception as e:
            print(f"error processing events {e}")

    def receive_message(self) -> Tuple[SimpleNamespace, bytes]:
        with self.lock:
            while len(self.incoming) == 0:
                self._process_events()

            ctx = self.incoming.popleft()
            msg = ctx.inbox.popleft()
        return ctx, msg

    def send_reply(self, ctx: SimpleNamespace, reply: bytes) -> None:
        ctx.outbox.append(reply)

    @classmethod
    def create(cls, endpoint: tuple[str, int], backlog: int = 0,
               packer: Any = None) -> 'TcpServerTransport':
        """Create new server transport.

        Instead of creating the socket yourself, you can call this function
        with the (host, port) endpoint.

        :param endpoint: The endpoint clients will connect to.
        :param backlog: The number of pending connections to allow.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(endpoint)
        sock.listen(backlog)
        return cls(sock, packer=packer)


class NonBlockingTcpClientTransport(NonBlockingClientTransport):
    """A TCP client transport that can send without waiting for the reply.

    Holds one connection open for the life of the transport and multiplexes
    requests over it, so it pairs with
    :py:class:`~tinyrpc.client_multiplexing.MultiplexingRPCClient` and a
    protocol that carries a correlation id.

    TODO: there is no reconnection.  The socket is opened once in __init__;
    if it drops, ``_service_write`` puts the pending buffer back and
    unregisters the socket, but nothing ever dials again, so the transport
    stays dead.  A connect-per-call transport gets recovery for free and this
    one does not, which matters wherever a service may be restarted
    underneath a long-lived client.  Fixing it means deciding on a retry
    policy (backoff, bounded attempts) and what to do with calls that were
    already in flight when the link went down.
    """

    def __init__(self,
                 endpoint: tuple[str, int],
                 packer: Any = None) -> None:
        self.endpoint = endpoint
        self.lock = threading.RLock()
        self.sel = selectors.DefaultSelector()
        self.incoming = queue.Queue()
        self.outgoing = deque()
        if packer is None:
            packer = TransportPacker()
        self.packer = packer
        self._process_timeout = 0.0001

        self.connect()

    def connect(self):
        conn_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_sock.connect(self.endpoint)
        # create a Transport context to be passed around as needed
        ctx = SimpleNamespace(sock=conn_sock,
                              packer=self.packer)
        # we are interested in read/write events on the socket
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self.sel.register(conn_sock, events, data=ctx)

    def _service_read(self, sock, ctx):
        """This method is called when activity happens on a client-
        connected socket.
        """
        # service incoming
        try:
            recv_data = ctx.packer.recv(sock)
        except ConnectionError as e:
            recv_data = b''
        if len(recv_data) > 0:
            self.incoming.put(recv_data)
        else:
            # socket appears to be closed at other end
            try:
                self.sel.unregister(sock)
            except (KeyError, ValueError):
                # raises KeyError if socket is not registered
                pass
            #ctx.sock = None
            try:
                sock.close()
            except Exception:
                pass

    def _service_write(self, sock, ctx):
        # service outgoing
        if len(self.outgoing) > 0:
            buf = self.outgoing.popleft()
            try:
                ctx.packer.send(sock, buf)
            except ConnectionError as e:
                # socket appears to be closed at other end
                # save buf in case we reconnect and send on another socket
                self.outgoing.appendleft(buf)
                try:
                    self.sel.unregister(sock)
                except (KeyError, ValueError):
                    # raises KeyError if socket is not registered
                    pass
                #ctx.sock = None
                try:
                    sock.close()
                except Exception:
                    pass

    def process_events(self):
        with self.lock:
            events = self.sel.select(timeout=self._process_timeout)
            out_events = []
            # process read events
            for key, mask in events:
                if mask & selectors.EVENT_READ:
                    sock, ctx = key.fileobj, key.data
                    self._service_read(sock, ctx)
                if mask & selectors.EVENT_WRITE:
                    out_events.append(key)

            # process pending writes
            for key in out_events:
                sock, ctx = key.fileobj, key.data
                self._service_write(sock, ctx)

    def receive_reply(self, timeout: Any = None) -> bytes:
        start_time = time.time()
        reply = None
        while True:
            try:
                reply = self.incoming.get(block=False)
                break
            except queue.Empty:
                self.process_events()

                if (timeout is not None and
                    time.time() - start_time > timeout):
                    raise TimeoutError("receive_reply() timed out")

        return reply

    def send_message_noblock(self, message: bytes) -> None:
        self.outgoing.append(message)

        self.process_events()

    def send_message(self, message: bytes, expect_reply: bool = True,
                     timeout: Any = None) -> bytes:

        self.send_message_noblock(message)

        if not expect_reply:
            return

        return self.receive_reply(timeout=timeout)


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

    def pack(self, msg):
        return msg

    def send(self, sock, msg):
        try:
            sock.sendall(msg)
        except socket.error as e:
            raise ConnectionError(f"socket send error: {e}")

    def recv(self, sock):
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

    def pack(self, msg):
        hdr = b'%s,%d' % (
            self.version, len(msg))
        # pad header to required size
        hdr += b' ' * (self.rpc_hdr_len - len(hdr))
        if len(hdr) != self.rpc_hdr_len:
            raise ValueError("RPC header len actual(%d) != expected(%d)" % (
                len(hdr), self.rpc_hdr_len))
        return hdr + msg

    def send(self, sock, msg):
        try:
            sock.sendall(self.pack(msg))
        except socket.error as e:
            raise ConnectionError(f"socket send error: {e}")

    def recv(self, sock):
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

    async def connect(self):
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

    async def start(self):
        host, port = self.endpoint
        while True:
            server = await asyncio.start_server(self._server, host, port)
            await server.serve_forever()

    async def _server(self, reader, writer):
        # create a Transport context to be passed around as needed
        ctx = SimpleNamespace(inbox=asyncio.Queue(), outbox=asyncio.Queue(),
                              ev_quit=asyncio.Event())
        t1 = asyncio.create_task(self._service_recv(reader, ctx))
        t2 = asyncio.create_task(self._service_send(writer, ctx))

        await t1
        await t2

    async def _service_recv(self, reader, ctx):
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

    async def _service_send(self, writer, ctx):
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

    def pack(self, msg):
        return msg

    async def send(self, writer, msg):
        #print("writer writing")
        writer.write(msg)
        await writer.drain()
        #print("writer wrote message")

    async def recv(self, reader):
        # read msg body from socket, fixed size
        #print("reader reading")
        msg = await reader.read(n=self.chunk_size)
        num_recvd = len(msg)
        if num_recvd == 0:
            raise ConnectionError("no bytes received")
        #print(f"reader got message {num_recvd} bytes")
        return msg
