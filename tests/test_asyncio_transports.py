#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the asyncio server and transports.

Three things in this package are called "async" and only these are
:py:mod:`asyncio`: :py:class:`~tinyrpc.server.AsyncioRPCServer` and the
``Asyncio*`` transports.  (:py:class:`~tinyrpc.client_multiplexing.
MultiplexingRPCClient` and the ``NonBlocking*`` transports are threaded.)

They had no tests at all, so what follows covers both what works and what
does not.  The limitations are pinned deliberately rather than left to be
rediscovered -- see the tests at the end of the file, which assert current
behaviour and say what fixing it would mean.

pytest-asyncio is not a dependency here, so each test drives its own loop
through :py:func:`asyncio.run`.
"""

import asyncio
import socket

import pytest

from tinyrpc.dispatch import RPCDispatcher
from tinyrpc.protocols.jsonrpc import JSONRPCProtocol
from tinyrpc.server import AsyncioRPCServer
from tinyrpc.transports.tcp import (AsyncioTcpClientTransport,
                                    AsyncioTcpServerTransport,
                                    AsyncioTransportPacker)

HOST = '127.0.0.1'


def free_port():
    """A port nothing is listening on.

    AsyncioTcpServerTransport takes its endpoint up front and never reports
    what it actually bound, so a port of 0 cannot be read back.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def make_dispatcher():
    dispatcher = RPCDispatcher()
    dispatcher.add_method(lambda a, b: a + b, 'add')
    dispatcher.add_method(lambda v: v, 'echo')

    def boom():
        raise ValueError('kaboom')

    dispatcher.add_method(boom, 'boom')
    return dispatcher


async def serve(port, dispatcher=None, protocol=None):
    """Start a server, returning it and the task running it."""
    transport = AsyncioTcpServerTransport((HOST, port))
    server = AsyncioRPCServer(transport, protocol or JSONRPCProtocol(),
                              dispatcher or make_dispatcher())
    task = asyncio.create_task(server.serve_forever())
    await asyncio.sleep(0.2)          # let it bind
    return server, task


async def shut_down(task, *transports):
    for transport in transports:
        close = getattr(transport, 'close', None)
        if close is not None:
            await close()
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass


# --------------------------------------------------------------- working --

def test_a_call_round_trips():
    async def main():
        port = free_port()
        _server, task = await serve(port)
        client = AsyncioTcpClientTransport((HOST, port))
        protocol = JSONRPCProtocol()
        try:
            request = protocol.create_request('add', [3, 4], None)
            reply = await client.send_message(request.serialize())
            return protocol.parse_reply(reply).result
        finally:
            await shut_down(task, client)

    assert asyncio.run(main()) == 7


def test_the_connection_is_opened_on_the_first_send():
    """Regression: the constructor used to call the connect() coroutine and
    drop it, so the transport had no reader or writer and could not be used
    at all."""
    async def main():
        port = free_port()
        _server, task = await serve(port)
        client = AsyncioTcpClientTransport((HOST, port))
        try:
            assert client.writer is None, "must not dial in the constructor"
            protocol = JSONRPCProtocol()
            await client.send_message(
                protocol.create_request('echo', ['hi'], None).serialize())
            assert client.writer is not None, "the first send should dial"
        finally:
            await shut_down(task, client)

    asyncio.run(main())


def test_several_calls_reuse_one_connection():
    async def main():
        port = free_port()
        _server, task = await serve(port)
        client = AsyncioTcpClientTransport((HOST, port))
        protocol = JSONRPCProtocol()
        try:
            results = []
            for n in range(5):
                request = protocol.create_request('echo', [n], None)
                reply = await client.send_message(request.serialize())
                results.append(protocol.parse_reply(reply).result)
            return results
        finally:
            await shut_down(task, client)

    assert asyncio.run(main()) == [0, 1, 2, 3, 4]


def test_a_failing_method_comes_back_as_an_error():
    async def main():
        port = free_port()
        _server, task = await serve(port)
        client = AsyncioTcpClientTransport((HOST, port))
        protocol = JSONRPCProtocol()
        protocol.raises_errors = False
        try:
            request = protocol.create_request('boom', [], None)
            reply = await client.send_message(request.serialize())
            return protocol.parse_reply(reply)
        finally:
            await shut_down(task, client)

    response = asyncio.run(main())
    assert 'kaboom' in str(response.error)


def test_the_client_can_be_closed_and_will_dial_again():
    async def main():
        port = free_port()
        _server, task = await serve(port)
        client = AsyncioTcpClientTransport((HOST, port))
        protocol = JSONRPCProtocol()
        try:
            await client.send_message(
                protocol.create_request('echo', ['a'], None).serialize())
            await client.close()
            assert client.writer is None

            reply = await client.send_message(
                protocol.create_request('echo', ['b'], None).serialize())
            return protocol.parse_reply(reply).result
        finally:
            await shut_down(task, client)

    assert asyncio.run(main()) == 'b'


# ------------------------------------------------------------- the packer --

def test_the_packer_round_trips_a_small_message():
    async def main():
        packer = AsyncioTransportPacker()
        reader = asyncio.StreamReader()
        reader.feed_data(b'hello')
        reader.feed_eof()
        return await packer.recv(reader)

    assert asyncio.run(main()) == b'hello'


def test_the_packer_refuses_an_empty_read():
    async def main():
        packer = AsyncioTransportPacker()
        reader = asyncio.StreamReader()
        reader.feed_eof()
        with pytest.raises(ConnectionError):
            await packer.recv(reader)

    asyncio.run(main())


# ---------------------------------------------------- pinned limitations --

def test_the_packer_has_no_framing():
    """Pinned, not endorsed.

    AsyncioTransportPacker reads one chunk of at most 4096 bytes with no
    length prefix, so a larger message arrives truncated and two smaller ones
    can arrive as one.  The threaded transports were moved onto
    TransportPackerRobust for exactly this reason; the asyncio ones have not
    been, and cannot carry a payload of any size until they are.
    """
    async def main():
        packer = AsyncioTransportPacker()

        reader = asyncio.StreamReader()
        reader.feed_data(b'x' * 10000)
        reader.feed_eof()
        big = await packer.recv(reader)

        reader = asyncio.StreamReader()
        reader.feed_data(b'one')
        reader.feed_data(b'two')
        reader.feed_eof()
        both = await packer.recv(reader)
        return big, both

    big, both = asyncio.run(main())
    assert len(big) == 4096, "a large message is truncated at chunk_size"
    assert both == b'onetwo', "two messages arrive as one"


def test_an_async_method_is_not_awaited():
    """Pinned, not endorsed.

    RPCDispatcher is synchronous: it calls the method and treats whatever
    comes back as the result.  Given an `async def` method that is a
    coroutine object, which then fails to serialize.  Supporting these needs
    an async-aware dispatcher -- upstream has one on its `asyncio` branch,
    predating the `caller` parameter this dispatcher now takes.
    """
    dispatcher = RPCDispatcher()

    async def slow_add(a, b):
        await asyncio.sleep(0)
        return a + b

    dispatcher.add_method(slow_add, 'slow_add')
    protocol = JSONRPCProtocol()

    request = protocol.parse_request(
        protocol.create_request('slow_add', [1, 2], None).serialize())
    response = dispatcher.dispatch(request, None)

    assert asyncio.iscoroutine(response.result), \
        "the coroutine is returned rather than awaited"
    with pytest.raises(TypeError):
        response.serialize()
    response.result.close()          # or Python warns it was never awaited


def test_the_asyncio_server_has_no_way_to_be_stopped():
    """Pinned, not endorsed.

    RPCServerExecutor grew an ev_quit and a stop(); AsyncioRPCServer did not,
    so its serve_forever() runs until its task is cancelled.  Cancelling
    works, which is what the tests above do, but there is no orderly
    shutdown that lets in-flight handlers finish.
    """
    assert not hasattr(AsyncioRPCServer, 'stop')
    assert 'ev_quit' not in AsyncioRPCServer.__init__.__code__.co_names


def test_the_server_transport_does_not_report_the_port_it_bound():
    """Pinned, not endorsed.

    The threaded transports expose `endpoint` after binding, so a service can
    ask for port 0 and register what it got.  This one takes its endpoint up
    front and never updates it, so port 0 cannot be used -- which is why
    these tests have to find a free port for themselves.
    """
    transport = AsyncioTcpServerTransport((HOST, 0))
    assert transport.endpoint == (HOST, 0)
