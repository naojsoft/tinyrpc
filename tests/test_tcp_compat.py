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
