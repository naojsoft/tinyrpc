#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Talking to a peer that is not ``tinyrpc``.

Standard msgpack-RPC over TCP has no length prefix: the msgpack stream is
self-delimiting, so the body is the whole message.
:py:class:`~tinyrpc.transports.tcp.TransportPackerRobust` adds one, which makes
a large reply arrive whole and lets a multiplexing client tell replies apart --
but it is a ``tinyrpc`` extension, and a peer that does not expect it sees a
malformed message and answers nothing.

So which packer a transport defaults to is a wire-format decision, not an
implementation detail.
"""

import socket
import threading

import pytest

msgpack = pytest.importorskip('msgpack')

from tinyrpc import RPCClient                                    # noqa: E402
from tinyrpc.protocols.msgpackrpc import MSGPACKRPCProtocol      # noqa: E402
from tinyrpc.transports.tcp import (AsyncTcpClientTransport,     # noqa: E402
                                    NonBlockingTcpClientTransport,
                                    TransportPacker)

HOST = '127.0.0.1'


class UnframedPeer:
    """A msgpack-RPC server that speaks the standard framing: none."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HOST, 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.saw = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                data = conn.recv(65536)
                if not data:
                    continue
                self.saw.append(data)
                _type, msgid, method, params = msgpack.unpackb(data, raw=False)
                conn.sendall(msgpack.packb([1, msgid, None, [method, params]],
                                           use_bin_type=True))
            except Exception:
                pass

    def close(self):
        self.sock.close()


@pytest.fixture
def peer():
    p = UnframedPeer()
    yield p
    p.close()


def test_the_old_name_still_talks_to_an_unframed_peer(peer):
    """Regression.  AsyncTcpClientTransport became a plain alias for the
    length-prefixed transport, so it began sending a 32-byte header that a
    standard msgpack-RPC peer cannot parse -- the call went out, nothing came
    back, and it surfaced as a timeout.  Importing still worked, which is what
    made it quiet."""
    client = RPCClient(MSGPACKRPCProtocol(),
                       AsyncTcpClientTransport((HOST, peer.port)))
    assert client.call('status', [1], {}, timeout=10.0) == ['status', [1]]

    assert peer.saw, "nothing reached the peer"
    assert not peer.saw[0].startswith(b'1.0,'), \
        "a length prefix went on the wire to a peer that does not expect one"


def test_the_new_transport_can_be_told_to_do_the_same(peer):
    """The default is the prefix, because that is what makes a large reply
    arrive whole; talking to an outside peer means saying so."""
    client = RPCClient(
        MSGPACKRPCProtocol(),
        NonBlockingTcpClientTransport((HOST, peer.port),
                                      packer=TransportPacker()))
    assert client.call('status', [], {}, timeout=10.0) == ['status', []]


def test_the_new_transport_frames_by_default(peer):
    """Stated so the difference between the two names is a decision rather
    than an accident."""
    client = RPCClient(MSGPACKRPCProtocol(),
                       NonBlockingTcpClientTransport((HOST, peer.port)))
    with pytest.raises(Exception):
        client.call('status', [], {}, timeout=2.0)

    assert peer.saw and peer.saw[0].startswith(b'1.0,'), \
        "expected the length prefix this transport is for"


# ----------------------------------------------- the pairs must agree --

#: Which client transport is meant to talk to which server transport, and
#: what framing that pair speaks.  ``AsyncTcpClientTransport`` is absent on
#: purpose: it exists to talk to peers that are not tinyrpc at all.
PAIRS = [
    ('ConnectionlessTcpClientTransport', 'ConnectionlessTcpServerTransport'),
    ('TcpClientTransport', 'TcpServerTransport'),
    ('NonBlockingTcpClientTransport', 'TcpServerTransport'),
    ('AsyncioTcpClientTransport', 'AsyncioTcpServerTransport'),
]


def default_packer(name):
    """Which packer a transport actually ends up with when given none.

    Built rather than read out of the source: what matters is the object on
    the instance, and a test that scrapes ``__init__`` starts lying the
    moment the default moves behind a function.
    """
    from tinyrpc.transports import tcp as mod

    cls = getattr(mod, name)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((HOST, 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    transport = None
    try:
        if 'Server' in name:
            transport = (cls((HOST, 0)) if name.startswith('Asyncio')
                         else cls(listener))
        else:
            transport = cls((HOST, port))
        return type(transport.packer).__name__
    finally:
        close = getattr(transport, 'close', None)
        if callable(close) and not name.startswith('Asyncio'):
            try:
                close()
            except Exception:
                pass
        listener.close()


@pytest.mark.parametrize('client_name,server_name', PAIRS)
def test_a_client_and_its_server_frame_the_same_way(client_name, server_name):
    """Regression, and a guard against the next one.

    TcpServerTransport was moved to length-prefixed framing and
    TcpClientTransport was left behind, so tinyrpc's own client could not
    talk to tinyrpc's own server.  Nothing caught it because nothing tested
    that pair -- and a framing mismatch does not raise, it times out.
    """
    assert default_packer(client_name) == default_packer(server_name), (
        "%s and %s disagree about framing, so they cannot talk to each other"
        % (client_name, server_name))


@pytest.mark.parametrize('client_name,_server', PAIRS)
def test_a_client_transport_accepts_the_timeout_the_client_passes(
        client_name, _server):
    """RPCClient.call() hands its keyword arguments straight to the
    transport, so one that does not take `timeout` turns
    ``call(..., timeout=5)`` into a TypeError instead of a timeout."""
    import inspect

    from tinyrpc.transports import tcp as mod
    params = inspect.signature(
        getattr(mod, client_name).send_message).parameters
    assert 'timeout' in params or any(
        p.kind is p.VAR_KEYWORD for p in params.values()), (
        "%s.send_message() rejects timeout=" % (client_name,))


# ------------------------------------------------ raw on both ends --

def echo_server(server_transport):
    """A running server on ``server_transport``, and its port."""
    from concurrent.futures import ThreadPoolExecutor

    from tinyrpc.dispatch import RPCDispatcher
    from tinyrpc.server.executor import RPCServerExecutor

    dispatcher = RPCDispatcher()
    dispatcher.add_method(lambda v: v, 'echo')
    executor = ThreadPoolExecutor(max_workers=4)
    server = RPCServerExecutor(server_transport, MSGPACKRPCProtocol(),
                               dispatcher, executor)
    server.start()
    return server, executor


def listening():
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, 0))
    sock.listen(8)
    return sock, sock.getsockname()[1]


def test_an_unframed_server_can_be_built():
    """The framing is the packer's, on a server exactly as on a client, so
    speaking the standard unframed msgpack-RPC is a matter of saying so at
    both ends rather than of which classes are used."""
    from tinyrpc.transports.tcp import (ConnectionlessTcpClientTransport,
                                        ConnectionlessTcpServerTransport)

    sock, port = listening()
    server, executor = echo_server(ConnectionlessTcpServerTransport(
        sock, packer=TransportPacker(), poll_timeout=0.2))
    try:
        client = RPCClient(MSGPACKRPCProtocol(),
                           ConnectionlessTcpClientTransport(
                               (HOST, port), packer=TransportPacker(),
                               timeout=5))
        assert client.call('echo', ['hi'], {}, timeout=5.0) == 'hi'
    finally:
        server.stop()
        executor.shutdown(wait=False)


def test_an_unframed_stateful_server_can_be_built_too():
    from tinyrpc.transports.tcp import TcpServerTransport

    sock, port = listening()
    server, executor = echo_server(TcpServerTransport(
        sock, packer=TransportPacker(), poll_timeout=0.2))
    try:
        client = RPCClient(MSGPACKRPCProtocol(),
                           AsyncTcpClientTransport((HOST, port)))
        assert client.call('echo', ['one'], {}, timeout=5.0) == 'one'
        assert client.call('echo', ['two'], {}, timeout=5.0) == 'two'
    finally:
        server.stop()
        executor.shutdown(wait=False)


def test_unframed_stops_working_at_one_read():
    """Which is the whole reason for the prefix, and the reason it is the
    default.  Raw framing hands the protocol whatever one recv() returned,
    so a message that did not fit arrives in pieces."""
    from tinyrpc.transports.tcp import TcpClientTransport, TcpServerTransport

    sock, port = listening()
    server, executor = echo_server(TcpServerTransport(
        sock, packer=TransportPacker(), poll_timeout=0.2))
    try:
        client = RPCClient(MSGPACKRPCProtocol(),
                           TcpClientTransport((HOST, port),
                                              packer=TransportPacker()))
        assert client.call('echo', ['x' * 1000], {}, timeout=5.0) == 'x' * 1000

        with pytest.raises(Exception):
            client.call('echo', ['x' * 100000], {}, timeout=5.0)
    finally:
        server.stop()
        executor.shutdown(wait=False)


def test_the_prefixed_default_carries_what_raw_cannot():
    from tinyrpc.transports.tcp import TcpClientTransport, TcpServerTransport

    sock, port = listening()
    server, executor = echo_server(TcpServerTransport(sock, poll_timeout=0.2))
    try:
        client = RPCClient(MSGPACKRPCProtocol(),
                           TcpClientTransport((HOST, port)))
        big = 'x' * 100000
        assert client.call('echo', [big], {}, timeout=10.0) == big
    finally:
        server.stop()
        executor.shutdown(wait=False)


def test_one_place_decides_the_default():
    """Every transport that frames asks the same function, so a client and
    its server cannot drift apart the way they did once."""
    import inspect

    from tinyrpc.transports import tcp as mod

    for client_name, server_name in PAIRS:
        for name in (client_name, server_name):
            source = inspect.getsource(getattr(mod, name).__init__)
            assert ('default_packer()' in source
                    or 'default_asyncio_packer()' in source), (
                "%s names its default packer itself instead of asking"
                % (name,))
