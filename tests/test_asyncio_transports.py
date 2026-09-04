#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the asyncio server and transports.

Three things in this package are called "async" and only these are
:py:mod:`asyncio`: :py:class:`~tinyrpc.server.AsyncioRPCServer` and the
``Asyncio*`` transports.  (:py:class:`~tinyrpc.client_multiplexing.
MultiplexingRPCClient` and the ``NonBlocking*`` transports are threaded.)

pytest-asyncio is not a dependency here, so each test drives its own loop
through :py:func:`asyncio.run`.
"""

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from tinyrpc.dispatch import RPCDispatcher
from tinyrpc.protocols.jsonrpc import JSONRPCProtocol
from tinyrpc.server import AsyncioRPCServer
from tinyrpc.transports import TransportTimeout
from tinyrpc.transports.tcp import (AsyncioTcpClientTransport,
                                    AsyncioTcpServerTransport,
                                    AsyncioTransportPacker,
                                    AsyncioTransportPackerRobust)

HOST = '127.0.0.1'


def make_dispatcher():
    dispatcher = RPCDispatcher()
    dispatcher.add_method(lambda a, b: a + b, 'add')
    dispatcher.add_method(lambda v: v, 'echo')

    def boom():
        raise ValueError('kaboom')

    async def slow_echo(v):
        await asyncio.sleep(0.2)
        return v

    async def async_boom():
        await asyncio.sleep(0)
        raise ValueError('async kaboom')

    def blocking_echo(v):
        time.sleep(0.2)
        return v

    dispatcher.add_method(boom, 'boom')
    dispatcher.add_method(slow_echo, 'slow_echo')
    dispatcher.add_method(async_boom, 'async_boom')
    dispatcher.add_method(blocking_echo, 'blocking_echo')
    return dispatcher


async def serve(dispatcher=None, protocol=None, executor=None):
    """Start a server on a port the OS chooses.

    :return: ``(server, task, port)`` -- the port actually bound, which the
        transport reports back after binding.
    """
    transport = AsyncioTcpServerTransport((HOST, 0))
    server = AsyncioRPCServer(transport, protocol or JSONRPCProtocol(),
                              dispatcher or make_dispatcher(),
                              executor=executor)
    task = asyncio.create_task(server.serve_forever())
    for _ in range(200):
        await asyncio.sleep(0.01)
        if transport.endpoint[1] != 0:
            break
    assert transport.endpoint[1] != 0, "the server never bound"
    return server, task, transport.endpoint[1]


async def shut_down(server, task, *clients):
    for client in clients:
        await client.close()
    await server.stop()
    task.cancel()
    try:
        await task
    except BaseException:
        pass


async def call(client, protocol, method, args, timeout=5.0):
    """Make one call.

    Bounded, so that a server which never answers -- because a handler
    raised, say, and its task's exception went unread -- fails the test
    rather than hanging it.
    """
    reply = await asyncio.wait_for(
        client.send_message(
            protocol.create_request(method, args, None).serialize()),
        timeout=timeout)
    return protocol.parse_reply(reply)


# --------------------------------------------------------------- calling --

def test_a_call_round_trips():
    async def main():
        server, task, port = await serve()
        client = AsyncioTcpClientTransport((HOST, port))
        try:
            return (await call(client, JSONRPCProtocol(), 'add', [3, 4])).result
        finally:
            await shut_down(server, task, client)

    assert asyncio.run(main()) == 7


def test_the_connection_is_opened_on_the_first_send():
    """Regression: the constructor used to call the connect() coroutine and
    drop it, so the transport had no reader or writer and was unusable."""
    async def main():
        server, task, port = await serve()
        client = AsyncioTcpClientTransport((HOST, port))
        try:
            assert client.writer is None, "must not dial in the constructor"
            await call(client, JSONRPCProtocol(), 'echo', ['hi'])
            assert client.writer is not None, "the first send should dial"
        finally:
            await shut_down(server, task, client)

    asyncio.run(main())


def test_several_calls_reuse_one_connection():
    async def main():
        server, task, port = await serve()
        client = AsyncioTcpClientTransport((HOST, port))
        protocol = JSONRPCProtocol()
        try:
            return [(await call(client, protocol, 'echo', [n])).result
                    for n in range(5)]
        finally:
            await shut_down(server, task, client)

    assert asyncio.run(main()) == [0, 1, 2, 3, 4]


def test_a_failing_method_comes_back_as_an_error():
    async def main():
        server, task, port = await serve()
        client = AsyncioTcpClientTransport((HOST, port))
        protocol = JSONRPCProtocol()
        protocol.raises_errors = False
        try:
            return await call(client, protocol, 'boom', [])
        finally:
            await shut_down(server, task, client)

    assert 'kaboom' in str(asyncio.run(main()).error)


def test_the_client_can_be_closed_and_will_dial_again():
    async def main():
        server, task, port = await serve()
        client = AsyncioTcpClientTransport((HOST, port))
        protocol = JSONRPCProtocol()
        try:
            await call(client, protocol, 'echo', ['a'])
            await client.close()
            assert client.writer is None
            return (await call(client, protocol, 'echo', ['b'])).result
        finally:
            await shut_down(server, task, client)

    assert asyncio.run(main()) == 'b'


# ---------------------------------------------------------------- framing --

def test_a_large_payload_arrives_whole():
    """Regression: the packer read one 4096-byte chunk with no length
    prefix, so anything larger arrived truncated."""
    async def main():
        server, task, port = await serve()
        client = AsyncioTcpClientTransport((HOST, port))
        payload = 'x' * 400000
        try:
            return (await call(client, JSONRPCProtocol(),
                               'echo', [payload])).result == payload
        finally:
            await shut_down(server, task, client)

    assert asyncio.run(main())


def test_the_framed_packer_round_trips_any_size():
    async def main():
        packer = AsyncioTransportPackerRobust()
        for payload in (b'', b'hi', b'x' * 100000):
            reader = asyncio.StreamReader()
            reader.feed_data(packer.pack(payload))
            reader.feed_eof()
            assert await packer.recv(reader) == payload

    asyncio.run(main())


def test_the_framed_packer_keeps_messages_apart():
    """Two messages back to back must not merge, which is what makes several
    calls on one connection possible."""
    async def main():
        packer = AsyncioTransportPackerRobust()
        reader = asyncio.StreamReader()
        reader.feed_data(packer.pack(b'one') + packer.pack(b'two'))
        reader.feed_eof()
        return await packer.recv(reader), await packer.recv(reader)

    assert asyncio.run(main()) == (b'one', b'two')


def test_the_framed_packer_reports_a_closed_connection():
    async def main():
        packer = AsyncioTransportPackerRobust()
        reader = asyncio.StreamReader()
        reader.feed_eof()
        with pytest.raises(ConnectionError):
            await packer.recv(reader)

    asyncio.run(main())


def test_the_unframed_packer_is_still_available():
    """Kept for a peer that speaks the old format, and still unframed --
    which is why it is no longer the default."""
    async def main():
        packer = AsyncioTransportPacker()
        reader = asyncio.StreamReader()
        reader.feed_data(b'x' * 10000)
        reader.feed_eof()
        return await packer.recv(reader)

    assert len(asyncio.run(main())) == 4096


# ------------------------------------------------------- async methods --

def test_an_async_method_is_awaited():
    """Regression: the dispatcher is synchronous, so an `async def` method
    used to come back as a coroutine object that then failed to serialize."""
    async def main():
        server, task, port = await serve()
        client = AsyncioTcpClientTransport((HOST, port))
        try:
            return (await call(client, JSONRPCProtocol(),
                               'slow_echo', ['hi'])).result
        finally:
            await shut_down(server, task, client)

    assert asyncio.run(main()) == 'hi'


def test_an_async_method_that_raises_becomes_an_error():
    async def main():
        server, task, port = await serve()
        client = AsyncioTcpClientTransport((HOST, port))
        protocol = JSONRPCProtocol()
        protocol.raises_errors = False
        try:
            return await call(client, protocol, 'async_boom', [])
        finally:
            await shut_down(server, task, client)

    assert 'async kaboom' in str(asyncio.run(main()).error)


def test_async_methods_overlap():
    """Three calls that each await 0.2s should take about 0.2s between them,
    which is the whole reason to serve on an event loop."""
    async def main():
        server, task, port = await serve()
        clients = [AsyncioTcpClientTransport((HOST, port)) for _ in range(3)]
        try:
            started = time.time()
            results = await asyncio.gather(*[
                call(c, JSONRPCProtocol(), 'slow_echo', [n])
                for n, c in enumerate(clients)])
            return [r.result for r in results], time.time() - started
        finally:
            await shut_down(server, task, *clients)

    results, elapsed = asyncio.run(main())
    assert results == [0, 1, 2]
    assert elapsed < 0.5, "took %.2fs, so they did not overlap" % elapsed


def test_a_blocking_method_stalls_the_loop_without_an_executor():
    """A synchronous method runs on the event loop, so a blocking one holds
    up every other call.  Pinned so the executor's value is visible."""
    async def main():
        server, task, port = await serve()
        clients = [AsyncioTcpClientTransport((HOST, port)) for _ in range(3)]
        try:
            started = time.time()
            await asyncio.gather(*[
                call(c, JSONRPCProtocol(), 'blocking_echo', [n])
                for n, c in enumerate(clients)])
            return time.time() - started
        finally:
            await shut_down(server, task, *clients)

    assert asyncio.run(main()) > 0.5, "0.2s x 3 should have run serially"


def test_an_executor_keeps_blocking_methods_off_the_loop():
    async def main():
        executor = ThreadPoolExecutor(max_workers=4)
        server, task, port = await serve(executor=executor)
        clients = [AsyncioTcpClientTransport((HOST, port)) for _ in range(3)]
        try:
            started = time.time()
            results = await asyncio.gather(*[
                call(c, JSONRPCProtocol(), 'blocking_echo', [n])
                for n, c in enumerate(clients)])
            return [r.result for r in results], time.time() - started
        finally:
            await shut_down(server, task, *clients)
            executor.shutdown(wait=False)

    results, elapsed = asyncio.run(main())
    assert results == [0, 1, 2]
    assert elapsed < 0.5, "took %.2fs, so the executor did not help" % elapsed


# ------------------------------------------------------------- lifecycle --

def test_the_server_reports_the_port_it_bound():
    """A port of 0 lets the OS choose, and the transport says what it got,
    so a service can register it."""
    async def main():
        server, task, port = await serve()
        try:
            assert port > 0
            return server.transport.endpoint
        finally:
            await shut_down(server, task)

    host, port = asyncio.run(main())
    assert host == HOST and port > 0


def test_the_server_can_be_stopped():
    """Regression: there was no stop(), so a serve loop ran until its task
    was cancelled."""
    async def main():
        server, task, port = await serve()
        await server.stop()
        await asyncio.sleep(0.2)
        assert server.ev_quit.is_set()

        # and the port is released
        client = AsyncioTcpClientTransport((HOST, port))
        with pytest.raises(OSError):
            await call(client, JSONRPCProtocol(), 'echo', ['hi'])
        task.cancel()

    asyncio.run(main())


def test_the_transport_gives_up_waiting_for_a_request():
    """What makes stopping possible: receive_message() must not block for
    ever, or the serve loop could never test its termination flag."""
    async def main():
        transport = AsyncioTcpServerTransport((HOST, 0), poll_timeout=0.2)
        started = time.time()
        with pytest.raises(TransportTimeout):
            await transport.receive_message()
        return time.time() - started

    assert asyncio.run(main()) < 2.0
