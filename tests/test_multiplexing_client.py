#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for MultiplexingRPCClient (formerly AsyncRPCClient).

The client keeps several calls in flight over one transport and matches each
reply to its request by correlation id.  Most of what can go wrong is in the
demultiplexing: a reply nobody is waiting for, a reply that never comes, or a
protocol that does not carry an id at all.  Those are what these cover.
"""

import threading
import time

import pytest

from tinyrpc.client import RPCClient
from tinyrpc.client_multiplexing import MultiplexingRPCClient, PendingCall
from tinyrpc.protocols.jsonrpc import JSONRPCProtocol
from tinyrpc.protocols.msgpackrpc import MSGPACKRPCProtocol
from tinyrpc.protocols.xmlrpc import XMLRPCProtocol

#: The protocols that can be multiplexed, i.e. that put an id on the reply.
CORRELATING_PROTOCOLS = [
    pytest.param(JSONRPCProtocol, id='jsonrpc'),
    pytest.param(MSGPACKRPCProtocol, id='msgpackrpc'),
]


class FakeTransport:
    """A non-blocking transport backed by a list, with no sockets involved.

    Requests land in :py:attr:`sent`; whatever is put in :py:attr:`inbox` is
    handed back by ``receive_reply`` in order.
    """

    def __init__(self):
        self.sent = []
        self.inbox = []
        self.fail_on_send = None

    def send_message_noblock(self, message):
        if self.fail_on_send is not None:
            raise self.fail_on_send
        self.sent.append(message)

    def receive_reply(self, timeout=None):
        if not self.inbox:
            raise TimeoutError('nothing waiting')
        return self.inbox.pop(0)

    def send_message(self, message, expect_reply=True):
        raise AssertionError('the multiplexing client must not block')


class BlockingOnlyTransport:
    """An ordinary transport, with no non-blocking interface at all."""

    def send_message(self, message, expect_reply=True):
        return b''


def serve(protocol, request_bytes, result):
    """Produce the reply a server would send for ``request_bytes``."""
    request = protocol.parse_request(request_bytes)
    return request.respond(result).serialize()


# --------------------------------------------------------- construction --

def test_rejects_a_protocol_without_reply_correlation():
    """XML-RPC has no id on the wire, so it cannot be multiplexed.

    Rejecting it here is much kinder than letting every reply arrive with
    unique_id=None and go unmatched.
    """
    with pytest.raises(TypeError) as excinfo:
        MultiplexingRPCClient(XMLRPCProtocol(allow_none=True),
                              FakeTransport())
    assert 'correlation id' in str(excinfo.value)


def test_rejects_a_transport_that_cannot_send_without_blocking():
    with pytest.raises(TypeError) as excinfo:
        MultiplexingRPCClient(JSONRPCProtocol(), BlockingOnlyTransport())
    assert 'send_message_noblock' in str(excinfo.value)


@pytest.mark.parametrize('protocol_cls', CORRELATING_PROTOCOLS)
def test_accepts_a_correlating_protocol(protocol_cls):
    MultiplexingRPCClient(protocol_cls(), FakeTransport())


def test_protocol_capability_flags_are_declared():
    assert JSONRPCProtocol.supports_reply_correlation is True
    assert MSGPACKRPCProtocol.supports_reply_correlation is True
    assert XMLRPCProtocol.supports_reply_correlation is False


# ------------------------------------------------------------- happy path --

@pytest.mark.parametrize('protocol_cls', CORRELATING_PROTOCOLS)
def test_begin_call_then_receive_reply(protocol_cls):
    protocol = protocol_cls()
    transport = FakeTransport()
    client = MultiplexingRPCClient(protocol, transport)

    ctx = client.begin_call('add', [1, 2], None)
    assert isinstance(ctx, PendingCall)
    assert not ctx.done()

    transport.inbox.append(serve(protocol, transport.sent[0], 3))
    client.process_incoming()

    assert ctx.done()
    assert client.receive_reply(ctx).result == 3


@pytest.mark.parametrize('protocol_cls', CORRELATING_PROTOCOLS)
def test_replies_are_matched_out_of_order(protocol_cls):
    """The point of the whole design: three calls in flight, replies back in
    a different order, each landing on the right pending call."""
    protocol = protocol_cls()
    transport = FakeTransport()
    client = MultiplexingRPCClient(protocol, transport)

    contexts = [client.begin_call('echo', [n], None) for n in (10, 20, 30)]
    assert len(transport.sent) == 3

    # Answer them back to front.
    for i in reversed(range(3)):
        transport.inbox.append(
            serve(protocol, transport.sent[i], (i + 1) * 10))
    for _ in range(3):
        client.process_incoming()

    assert [client.receive_reply(c).result for c in contexts] == [10, 20, 30]


@pytest.mark.parametrize('protocol_cls', CORRELATING_PROTOCOLS)
def test_the_board_is_emptied_as_calls_complete(protocol_cls):
    protocol = protocol_cls()
    transport = FakeTransport()
    client = MultiplexingRPCClient(protocol, transport)

    ctx = client.begin_call('add', [1, 2], None)
    assert len(client.tracking_board) == 1

    transport.inbox.append(serve(protocol, transport.sent[0], 3))
    client.process_incoming()
    client.receive_reply(ctx)

    assert client.tracking_board == {}


# ------------------------------------------------------------ regressions --

def test_a_reply_the_protocol_rejects_does_not_kill_the_receive_loop():
    """A reply to a request this client never sent must not take the loop
    down.

    Note which guard this exercises: JSONRPCProtocol does its *own* id
    tracking in ``_pending_replies`` and raises UnexpectedIDError from
    parse_reply() for an id it never issued, so such a reply never reaches
    the tracking board at all.  This covers process_incoming()'s guard around
    parsing.  The guard around *dispatching* is covered by
    test_a_late_reply_after_a_timeout_is_discarded_quietly, where the
    protocol accepts the reply but no call is waiting for it.
    """
    protocol = JSONRPCProtocol()
    transport = FakeTransport()
    client = MultiplexingRPCClient(protocol, transport)

    # A reply to a request this client never sent.
    orphan_request = JSONRPCProtocol().create_request('add', [1, 2],
                                                      None).serialize()
    transport.inbox.append(serve(protocol, orphan_request, 3))

    ev_quit = threading.Event()
    errors = []

    def run():
        try:
            client.receive_forever(ev_quit)
        except Exception as e:      # pragma: no cover - the bug being fixed
            errors.append(e)

    thread = threading.Thread(target=run)
    thread.start()
    try:
        # Give the loop time to swallow the orphan, then show it still works.
        time.sleep(0.2)
        assert not errors, "receive_forever died on an unmatched reply"

        ctx = client.begin_call('add', [1, 2], None)
        transport.inbox.append(serve(protocol, transport.sent[-1], 7))
        assert client.receive_reply(ctx, timeout=5.0).result == 7
    finally:
        ev_quit.set()
        thread.join(timeout=5.0)

    assert not errors


def test_a_timed_out_call_is_removed_from_the_board():
    """Regression: receive_reply() raised before deleting the entry, so a
    timed-out id stayed on the board forever -- a leak, and it would later
    collide with a reused id."""
    protocol = JSONRPCProtocol()
    client = MultiplexingRPCClient(protocol, FakeTransport())

    ctx = client.begin_call('add', [1, 2], None)
    assert len(client.tracking_board) == 1

    with pytest.raises(TimeoutError):
        client.receive_reply(ctx, timeout=0.05)

    assert client.tracking_board == {}, "timed-out call left on the board"


def test_a_late_reply_after_a_timeout_is_discarded_quietly():
    """The two fixes above have to compose: once a call times out its entry
    is gone, so the late reply is unmatched -- and must be dropped, not
    raised.

    Unlike the test above, the protocol *accepts* this reply (it issued the
    id, so it is in ``_pending_replies``); it is the tracking board that has
    no call waiting.  So this is what covers the dispatch guard.
    """
    protocol = JSONRPCProtocol()
    transport = FakeTransport()
    client = MultiplexingRPCClient(protocol, transport)

    ctx = client.begin_call('add', [1, 2], None)
    with pytest.raises(TimeoutError):
        client.receive_reply(ctx, timeout=0.05)

    transport.inbox.append(serve(protocol, transport.sent[0], 3))
    client.process_incoming()          # must not raise


def test_a_late_reply_does_not_kill_the_receive_loop_either():
    """The same case as above, but through receive_forever(), so that the
    loop's survival is pinned and not just process_incoming()'s."""
    protocol = JSONRPCProtocol()
    transport = FakeTransport()
    client = MultiplexingRPCClient(protocol, transport)

    ctx = client.begin_call('add', [1, 2], None)
    with pytest.raises(TimeoutError):
        client.receive_reply(ctx, timeout=0.05)

    ev_quit = threading.Event()
    errors = []

    def run():
        try:
            client.receive_forever(ev_quit)
        except Exception as e:      # pragma: no cover - the bug being fixed
            errors.append(e)

    thread = threading.Thread(target=run)
    thread.start()
    try:
        transport.inbox.append(serve(protocol, transport.sent[0], 3))
        time.sleep(0.2)
        assert not errors, "receive_forever died on a late reply"

        # ... and the client still works afterwards.
        ctx2 = client.begin_call('add', [3, 4], None)
        transport.inbox.append(serve(protocol, transport.sent[-1], 7))
        assert client.receive_reply(ctx2, timeout=5.0).result == 7
    finally:
        ev_quit.set()
        thread.join(timeout=5.0)

    assert not errors


def test_a_timed_out_call_is_forgotten_by_the_protocol_too():
    """Regression: JSONRPCProtocol keeps its own record of ids it expects
    replies for, and only a reply cleared it -- so a call that timed out
    leaked one layer below the tracking board, where fixing the board could
    not reach it.  The client is the only party that knows the call is over,
    so it has to say so.
    """
    protocol = JSONRPCProtocol()
    client = MultiplexingRPCClient(protocol, FakeTransport())

    for _ in range(5):
        ctx = client.begin_call('add', [1, 2], None)
        with pytest.raises(TimeoutError):
            client.receive_reply(ctx, timeout=0.01)

    assert client.tracking_board == {}, "the client's own board is cleaned"
    assert protocol._pending_replies == {}, "the protocol's record is too"


def test_call_accepts_a_timeout():
    """Regression: the override dropped the timeout parameter that
    RPCClient.call() takes, so a call could only ever block forever."""
    import inspect

    parent = inspect.signature(RPCClient.call).parameters
    child = inspect.signature(MultiplexingRPCClient.call).parameters
    assert 'timeout' in child
    assert list(child) == list(parent)

    client = MultiplexingRPCClient(JSONRPCProtocol(), FakeTransport())
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        client.call('add', [1, 2], None, timeout=0.1)
    assert time.monotonic() - start < 5.0


def test_send_and_handle_reply_keeps_the_inherited_signature():
    """Regression: the override dropped ``transport``, so the inherited
    call_all() -- which passes positionally as (req, False, tr, True) -- put
    a transport into no_exception and True into timeout."""
    import inspect

    parent = list(inspect.signature(RPCClient._send_and_handle_reply)
                  .parameters)
    child = list(inspect.signature(
        MultiplexingRPCClient._send_and_handle_reply).parameters)
    assert child == parent


def test_a_failed_send_does_not_leave_the_call_on_the_board():
    protocol = JSONRPCProtocol()
    transport = FakeTransport()
    transport.fail_on_send = ConnectionError('link down')
    client = MultiplexingRPCClient(protocol, transport)

    with pytest.raises(ConnectionError):
        client.begin_call('add', [1, 2], None)

    assert client.tracking_board == {}


def test_tinyrpc_timeout_error_is_catchable_as_the_builtin():
    """Regression: tinyrpc.exc.TimeoutError did not derive from the builtin,
    so `except TimeoutError` in the receive loop caught the TCP transport's
    timeout but not the 0mq transport's."""
    from tinyrpc.exc import TimeoutError as TinyrpcTimeoutError

    assert issubclass(TinyrpcTimeoutError, TimeoutError)

    protocol = JSONRPCProtocol()

    class TinyrpcTimeoutTransport(FakeTransport):
        def receive_reply(self, timeout=None):
            raise TinyrpcTimeoutError()

    client = MultiplexingRPCClient(protocol, TinyrpcTimeoutTransport())
    client.process_incoming()          # must not raise


def test_a_malformed_reply_is_dropped_not_raised():
    protocol = JSONRPCProtocol()
    transport = FakeTransport()
    transport.inbox.append(b'this is not a valid reply')
    client = MultiplexingRPCClient(protocol, transport)

    client.process_incoming()          # must not raise


# ------------------------------------------------------------- threading --

@pytest.mark.parametrize('protocol_cls', CORRELATING_PROTOCOLS)
def test_a_reply_arriving_before_the_wait_is_not_missed(protocol_cls):
    """The reply may land between begin_call() and receive_reply(); the
    condition has to be re-checked under the lock rather than waited on
    blindly."""
    protocol = protocol_cls()
    transport = FakeTransport()
    client = MultiplexingRPCClient(protocol, transport)

    ctx = client.begin_call('add', [1, 2], None)
    transport.inbox.append(serve(protocol, transport.sent[0], 3))
    client.process_incoming()          # reply arrives first

    assert client.receive_reply(ctx, timeout=1.0).result == 3


@pytest.mark.parametrize('protocol_cls', CORRELATING_PROTOCOLS)
def test_concurrent_callers_each_get_their_own_result(protocol_cls):
    """Several threads calling at once over one transport."""
    protocol = protocol_cls()
    transport = FakeTransport()
    lock = threading.Lock()
    client = MultiplexingRPCClient(protocol, transport)

    n_calls = 12
    results = {}

    # Serve every request as it is sent, from a thread of its own, so the
    # callers really are overlapping.
    stop = threading.Event()

    def responder():
        served = 0
        while not stop.is_set():
            with lock:
                pending = transport.sent[served:]
                if pending:
                    for raw in pending:
                        request = protocol.parse_request(raw)
                        transport.inbox.append(
                            request.respond(request.args[0] * 2).serialize())
                        served += 1
            client.process_incoming()
            time.sleep(0.001)

    responder_thread = threading.Thread(target=responder)
    responder_thread.start()

    def caller(n):
        results[n] = client.call('double', [n], None, timeout=10.0)

    threads = [threading.Thread(target=caller, args=(n,))
               for n in range(n_calls)]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15.0)
    finally:
        stop.set()
        responder_thread.join(timeout=5.0)

    assert results == {n: n * 2 for n in range(n_calls)}
    assert client.tracking_board == {}


# ---------------------------------------------------------------- naming --

def test_old_names_still_resolve():
    """The renames keep working for code that has not been updated yet."""
    from tinyrpc.client_multiplexing import AsyncRPCClient
    from tinyrpc.transports.tcp import (AsyncTcpClientTransport,
                                        NonBlockingTcpClientTransport)

    assert AsyncRPCClient is MultiplexingRPCClient
    assert AsyncTcpClientTransport is NonBlockingTcpClientTransport
