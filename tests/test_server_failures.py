#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""What happens when handling a request goes wrong.

A handler runs on a worker -- an Executor's thread or an asyncio Task -- and
both store an exception where nobody looks unless asked.  With the Future or
the Task discarded, as they were, a handler that failed sent no reply and
left no trace: the caller simply waited out its timeout.

The realistic way to get there is a result the protocol cannot encode.
dispatch() turns an exception *inside* a method into an error response, so
the method itself failing is handled; it is serializing the response
afterwards that can still blow up.
"""

import asyncio
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from tinyrpc.dispatch import RPCDispatcher
from tinyrpc.protocols.jsonrpc import JSONRPCProtocol
from tinyrpc.server import AsyncioRPCServer
from tinyrpc.server.executor import RPCServerExecutor
from tinyrpc.transports import ServerTransport, TransportTimeout
from tinyrpc.transports.tcp import (AsyncioTcpClientTransport,
                                    AsyncioTcpServerTransport)

HOST = '127.0.0.1'


class Unserializable:
    """A result JSON cannot encode, so response.serialize() will raise."""


def make_dispatcher():
    dispatcher = RPCDispatcher()
    dispatcher.add_method(lambda v: v, 'echo')
    dispatcher.add_method(lambda: Unserializable(), 'unserializable')

    async def async_unserializable():
        await asyncio.sleep(0)
        return Unserializable()

    dispatcher.add_method(async_unserializable, 'async_unserializable')
    return dispatcher


class OneShotTransport(ServerTransport):
    """Hands over one message, then reports nothing further, and records
    whatever reply comes back."""

    def __init__(self, message):
        self.message = message
        self.replies = []
        self.delivered = threading.Event()

    def receive_message(self):
        if self.message is None:
            raise TransportTimeout()
        message, self.message = self.message, None
        return 'ctx', message

    def send_reply(self, context, reply):
        self.replies.append(reply)
        self.delivered.set()


# ------------------------------------------------------------- threaded --

def test_a_handler_that_cannot_serialize_still_answers():
    """Regression: the Future was discarded, so this sent no reply at all
    and the caller waited out its timeout."""
    protocol = JSONRPCProtocol()
    request = protocol.create_request('unserializable', [], None)
    transport = OneShotTransport(request.serialize())

    executor = ThreadPoolExecutor(max_workers=2)
    server = RPCServerExecutor(transport, protocol, make_dispatcher(),
                               executor, ev_quit=threading.Event())
    server.start()
    try:
        assert transport.delivered.wait(timeout=10), \
            "no reply was sent for a handler that failed"
    finally:
        server.stop()
        executor.shutdown(wait=False)

    protocol.raises_errors = False
    response = protocol.parse_reply(transport.replies[0])
    assert response.unique_id == request.unique_id, \
        "the error should name the call it belongs to"
    assert response.error


def test_a_failed_handler_is_logged(caplog):
    protocol = JSONRPCProtocol()
    transport = OneShotTransport(
        protocol.create_request('unserializable', [], None).serialize())

    executor = ThreadPoolExecutor(max_workers=2)
    server = RPCServerExecutor(transport, protocol, make_dispatcher(),
                               executor, ev_quit=threading.Event())
    with caplog.at_level(logging.ERROR):
        server.start()
        try:
            transport.delivered.wait(timeout=10)
            time.sleep(0.2)
        finally:
            server.stop()
            executor.shutdown(wait=False)

    assert any('error handling a request' in r.message or
               'handler failed' in r.message for r in caplog.records), \
        "the failure was not reported anywhere"


def test_an_ordinary_call_is_unaffected():
    protocol = JSONRPCProtocol()
    request = protocol.create_request('echo', ['hi'], None)
    transport = OneShotTransport(request.serialize())

    executor = ThreadPoolExecutor(max_workers=2)
    server = RPCServerExecutor(transport, protocol, make_dispatcher(),
                               executor, ev_quit=threading.Event())
    server.start()
    try:
        assert transport.delivered.wait(timeout=10)
    finally:
        server.stop()
        executor.shutdown(wait=False)

    assert protocol.parse_reply(transport.replies[0]).result == 'hi'


# -------------------------------------------------------------- asyncio --

async def _serve():
    transport = AsyncioTcpServerTransport((HOST, 0), poll_timeout=0.2)
    server = AsyncioRPCServer(transport, JSONRPCProtocol(), make_dispatcher())
    task = asyncio.create_task(server.serve_forever())
    for _ in range(200):
        await asyncio.sleep(0.01)
        if transport.endpoint[1] != 0:
            break
    return server, task, transport.endpoint[1]


async def _call(port, method):
    protocol = JSONRPCProtocol()
    protocol.raises_errors = False
    client = AsyncioTcpClientTransport((HOST, port))
    try:
        reply = await asyncio.wait_for(
            client.send_message(
                protocol.create_request(method, [], None).serialize()),
            timeout=10.0)
        return protocol.parse_reply(reply)
    finally:
        await client.close()


@pytest.mark.parametrize('method', ['unserializable',
                                    'async_unserializable'])
def test_the_asyncio_server_answers_a_failed_handler(method):
    """Regression: the Task was discarded, so nothing was sent and the
    failure surfaced only much later, if at all, as "Task exception was
    never retrieved"."""
    async def main():
        server, task, port = await _serve()
        try:
            return await _call(port, method)
        finally:
            await server.stop()
            task.cancel()

    response = asyncio.run(main())
    assert response.error, "expected an error reply, not a result"


def test_the_asyncio_server_still_answers_an_ordinary_call():
    async def main():
        server, task, port = await _serve()
        protocol = JSONRPCProtocol()
        client = AsyncioTcpClientTransport((HOST, port))
        try:
            reply = await asyncio.wait_for(
                client.send_message(
                    protocol.create_request('echo', ['hi'],
                                            None).serialize()),
                timeout=10.0)
            return protocol.parse_reply(reply).result
        finally:
            await client.close()
            await server.stop()
            task.cancel()

    assert asyncio.run(main()) == 'hi'
