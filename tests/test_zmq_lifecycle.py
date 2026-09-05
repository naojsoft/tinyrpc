#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Starting and stopping the 0mq server transport.

A 0mq socket must not be touched by more than one thread, which is why one
thread owns it and the others hand it work.  That makes shutdown the delicate
part: the socket has to be closed exactly once, by whoever is entitled to,
and never while the owning thread is still polling it.
"""

import threading
import time

import pytest

zmq = pytest.importorskip('zmq')

from tinyrpc.transports.zmq import ZmqServerTransport  # noqa: E402


@pytest.fixture
def context():
    ctx = zmq.Context()
    yield ctx
    ctx.term()


def watch_threads():
    """Collect exceptions from threads, which otherwise only print."""
    failures = []
    original = threading.excepthook

    def hook(args):
        failures.append(args.exc_value)

    threading.excepthook = hook
    return failures, lambda: setattr(threading, 'excepthook', original)


def test_a_second_stop_leaves_the_socket_to_the_first(context):
    """Regression.  stop() clears _thread, so a second stop saw None and read
    it as "never started" -- then closed the socket while the first stop's
    thread was still polling it.  0mq reports that as "Socket operation on
    non-socket", raised on a thread nobody is watching, so it surfaced as a
    traceback beside otherwise correct results.

    Two stops is the ordinary case rather than a contrived one: a server's
    serve loop stops its transport when it exits, and whoever asked the
    server to stop does too.

    The interleaving is set up rather than raced for.  Both stops wake the
    socket thread immediately, so the window where it is still polling is a
    few microseconds wide and a timing test hits it almost never -- it
    passed against the bug.  So this puts the transport in exactly the state
    the first stop leaves behind while it is joining, and asks the second
    what it does.
    """
    transport = ZmqServerTransport.create(context, 'tcp://127.0.0.1:*')
    transport.start()
    time.sleep(0.2)                 # let the socket thread reach its poll

    # What the first stop() has done by the time it starts joining.
    with transport._lifecycle:
        thread, transport._thread = transport._thread, None

    try:
        transport.stop()            # the second one
        assert not transport.socket.closed, \
            "closed the socket while the owning thread was still polling it"
    finally:
        transport._ev_quit.set()
        thread.join(timeout=5)


def test_stopping_twice_at_once_is_survivable(context):
    """The same thing raced for rather than arranged, which is what actually
    happens in a server shutdown."""
    transport = ZmqServerTransport.create(context, 'tcp://127.0.0.1:*')
    transport.start()
    time.sleep(0.2)

    failures, restore = watch_threads()
    try:
        stops = [threading.Thread(target=transport.stop) for _ in range(2)]
        for thread in stops:
            thread.start()
        for thread in stops:
            thread.join(timeout=10)
            assert not thread.is_alive(), "stop() did not return"
        time.sleep(0.3)             # let the socket thread finish unwinding
    finally:
        restore()

    assert not failures, "the socket thread died: %r" % (failures,)
    assert transport.socket.closed, "and it must still end up closed"


def test_stopping_one_that_never_started_still_closes_it(context):
    """Nobody else will, so this path has to close the socket itself."""
    transport = ZmqServerTransport.create(context, 'tcp://127.0.0.1:*')
    transport.stop()
    assert transport.socket.closed


def test_stop_after_a_normal_run_closes_everything(context):
    transport = ZmqServerTransport.create(context, 'tcp://127.0.0.1:*')
    transport.start()
    time.sleep(0.2)
    transport.stop()

    assert transport.socket.closed
    assert transport._shut


def test_starting_twice_makes_one_thread(context):
    transport = ZmqServerTransport.create(context, 'tcp://127.0.0.1:*')
    try:
        transport.start()
        first = transport._thread
        transport.start()
        assert transport._thread is first
    finally:
        transport.stop()
