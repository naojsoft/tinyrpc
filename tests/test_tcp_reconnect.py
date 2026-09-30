#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""A held TCP connection, and what it costs when one dies.

:py:class:`~tinyrpc.transports.tcp.NonBlockingTcpClientTransport` holds one
connection open and dials again when it drops, which is what makes a client
outlive the service it calls.  The dialling is the easy half.  The other half
is letting go of the connection that died: a reader thread is blocked in
recv() on it, and a thread that is never reclaimed is a leak that accumulates
for as long as the process runs -- one per disconnection, which for a service
that is restarted nightly is one per night.
"""

import socket
import threading
import time

import pytest

msgpack = pytest.importorskip('msgpack')

from tinyrpc.protocols.msgpackrpc import MSGPACKRPCProtocol     # noqa: E402
from tinyrpc.transports.tcp import (NonBlockingTcpClientTransport,  # noqa: E402
                                    TcpServerTransport)

HOST = '127.0.0.1'

#: What :py:class:`NonBlockingTcpClientTransport` names its reader threads.
READER = 'tcp-client-reader'


def readers():
    """The reader threads alive right now.

    A set of the thread objects rather than a count: the suite may run
    several of these at once, so what matters is whether *these* went away.
    """
    return {t for t in threading.enumerate() if t.name == READER}


@pytest.fixture
def echo():
    """A server that holds each connection open.  Yields its port."""
    from concurrent.futures import ThreadPoolExecutor

    from tinyrpc.dispatch import RPCDispatcher
    from tinyrpc.server.executor import RPCServerExecutor

    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, 0))
    sock.listen(8)
    port = sock.getsockname()[1]

    dispatcher = RPCDispatcher()
    dispatcher.add_method(lambda v: v, 'echo')
    # A reply that will not have arrived by the time the connection dies.
    dispatcher.add_method(lambda secs: time.sleep(secs) or 'slept', 'slow')
    executor = ThreadPoolExecutor(max_workers=4)
    server = RPCServerExecutor(TcpServerTransport(sock, poll_timeout=0.2),
                               MSGPACKRPCProtocol(), dispatcher, executor)
    server.start()
    try:
        yield port
    finally:
        server.stop()
        executor.shutdown(wait=False)


def connected(port, **kwargs):
    """A transport with a live connection and a reader on it."""
    transport = NonBlockingTcpClientTransport((HOST, port), **kwargs)
    transport.connect()
    assert transport.connected
    return transport


def gone(threads, timeout=5.0):
    """Wait for every thread in ``threads`` to finish.  True if they did."""
    deadline = time.monotonic() + timeout
    for t in threads:
        t.join(timeout=max(0.0, deadline - time.monotonic()))
    return not any(t.is_alive() for t in threads)


# ------------------------------------------------- letting go of a drop --

def test_a_drop_the_sender_noticed_leaves_no_reader_behind(echo):
    """Regression.  close() releases the descriptor but does not interrupt a
    recv() already in progress on another thread: the reader stayed in the
    syscall and the thread was never reclaimed.  Only the reader's own path
    out -- noticing the far end had gone -- freed one, and a send that failed
    first, which is how a drop is usually noticed, leaked one every time."""
    transport = connected(echo)
    reader = transport._reader
    assert reader in readers()

    # Exactly what send_message_noblock does when a send fails.
    transport._drop(transport._generation, 'simulated send failure')

    assert gone([reader]), 'the reader is still blocked on the closed socket'
    transport.close()


def test_closing_leaves_no_reader_behind(echo):
    """close() had the same hole as _drop(), for the same reason."""
    transport = connected(echo)
    reader = transport._reader

    transport.close()

    assert gone([reader])


def test_many_drops_do_not_accumulate_readers(echo):
    """One reader per connection, not one per connection ever made."""
    transport = connected(echo, reconnect_interval=0)
    started = []
    for _ in range(8):
        started.append(transport._reader)
        transport._drop(transport._generation, 'again')
        transport.connect()

    assert gone(started), 'a reader outlived its connection'
    live = readers() & (set(started) | {transport._reader})
    assert live == {transport._reader}, 'more than one reader is alive'
    transport.close()


# --------------------------------------------------- dialling again --

def test_the_next_send_dials_again(echo):
    """Lazily and repeatedly, which is what lets a client outlive a service
    restart."""
    transport = connected(echo, reconnect_interval=0)
    protocol = MSGPACKRPCProtocol()

    def call(value):
        request = protocol.create_request('echo', [value])
        reply = transport.send_message(request.serialize(), timeout=5.0)
        return protocol.parse_reply(reply).result

    assert call('before') == 'before'

    transport._drop(transport._generation, 'simulated drop')
    assert not transport.connected

    assert call('after') == 'after', 'never dialled again'
    assert transport.connected
    transport.close()


def test_the_redial_is_paced(echo):
    """A service that is down should be asked politely rather than
    continuously, so a dial too soon after the last one is refused."""
    transport = connected(echo, reconnect_interval=30.0)
    transport._drop(transport._generation, 'simulated drop')

    with pytest.raises(ConnectionError) as caught:
        transport.connect()
    assert 'not reconnecting' in str(caught.value)

    transport.close()


# ------------------------------------------- not waiting for the lost --

def test_a_waiter_is_not_left_waiting_for_a_reply_that_cannot_come(echo):
    """The reply to a call that was in flight when the connection died is
    gone.  A caller that gave no timeout would otherwise wait for it for
    ever -- which a per-call connection never had to answer for, since there
    the failure surfaced at dial time."""
    transport = connected(echo)
    protocol = MSGPACKRPCProtocol()
    transport.send_message_noblock(
        protocol.create_request('slow', [5]).serialize())

    outcome = {}

    def wait():
        try:
            outcome['reply'] = transport.receive_reply(timeout=None)
        except Exception as e:
            outcome['raised'] = e

    waiter = threading.Thread(target=wait)
    waiter.start()
    # Let the request go out, then take the connection away underneath it.
    time.sleep(0.2)
    transport._drop(transport._generation, 'simulated drop')

    waiter.join(timeout=10)
    assert not waiter.is_alive(), 'the waiter is still waiting'
    assert isinstance(outcome.get('raised'), ConnectionError), outcome
    transport.close()
