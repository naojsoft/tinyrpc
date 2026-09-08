#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""XML-RPC batching, which is ``system.multicall``.

Three things made the original implementation unusable, and they are worth
naming because each fails differently:

* the request was serialized as a list of bare argument arrays, where the
  convention -- and what our own parser expected -- is a list of
  ``{'methodName': ..., 'params': [...]}`` structs;
* the response was serialized with both ``methodname`` and ``methodresponse``,
  and ``methodname`` wins, so a *reply* went out as a ``<methodCall>``;
* a reply could not be recognised as a batch at all, because XML-RPC puts no
  id on the wire and a multicall reply is an ordinary ``<methodResponse>``
  carrying an array -- indistinguishable, by inspection, from a single call
  that returned an array.

The first two are wire-format bugs.  The third is not a bug but a property of
the protocol: only the caller knows what it asked for, so the caller says.
"""

import threading
import xmlrpc.client
from concurrent.futures import ThreadPoolExecutor
from socketserver import ThreadingMixIn
from xmlrpc.server import SimpleXMLRPCServer

import pytest

from tinyrpc.client import RPCClient
from tinyrpc.dispatch import RPCDispatcher
from tinyrpc.protocols.xmlrpc import (XMLRPCBatchResponse, XMLRPCErrorResponse,
                                      XMLRPCProtocol, XMLRPCSuccessResponse)
from tinyrpc.server.executor import RPCServerExecutor
from tinyrpc.transports.http_client import HttpClientTransport
from tinyrpc.transports.http_server import HttpServerTransport

HOST = '127.0.0.1'


def add(a, b):
    return a + b


def sub(a, b):
    return a - b


def boom():
    raise ValueError('kaboom')


def protocol():
    return XMLRPCProtocol(allow_none=True, allow_large_ints=True)


def dispatcher():
    d = RPCDispatcher()
    d.add_method(add, 'add')
    d.add_method(sub, 'sub')
    d.add_method(boom, 'boom')
    return d


def batch_of(client, calls):
    request = client.create_batch_request()
    for method, args in calls:
        request.append(client.create_request(method, args))
    return request


# --------------------------------------------------------- the wire --

def test_a_batch_request_is_a_multicall():
    wire = batch_of(protocol(), [('add', [7, 3]), ('sub', [7, 3])]).serialize()

    params, method = xmlrpc.client.loads(wire)
    assert method == 'system.multicall'
    assert params == ([{'methodName': 'add', 'params': [7, 3]},
                       {'methodName': 'sub', 'params': [7, 3]}],), \
        "the convention is a struct per call, not a bare argument array"


def test_a_batch_reply_is_a_reply():
    """It went out as a <methodCall> before, because dumps() lets methodname
    win over methodresponse and it was given both."""
    client, server = protocol(), protocol()
    arrived = server.parse_request(
        batch_of(client, [('add', [7, 3])]).serialize())
    wire = dispatcher().dispatch(arrived).serialize()

    assert b'<methodResponse>' in wire
    assert b'<methodCall>' not in wire


# ------------------------------------------------------ round trip --

def test_a_batch_round_trips():
    client, server = protocol(), protocol()

    arrived = server.parse_request(
        batch_of(client, [('add', [7, 3]), ('sub', [7, 3])]).serialize())
    assert [r.method for r in arrived] == ['add', 'sub']

    replies = client.parse_batch_reply(
        dispatcher().dispatch(arrived).serialize())
    assert isinstance(replies, XMLRPCBatchResponse)
    assert [r.result for r in replies] == [10, 4]


def test_a_failure_in_a_batch_stays_a_failure():
    """Every entry is either a one-element array or a fault struct.  Reading
    both the same way turned every fault into KeyError(0)."""
    client, server = protocol(), protocol()
    arrived = server.parse_request(
        batch_of(client, [('add', [7, 3]), ('nope', [1]),
                          ('boom', [])]).serialize())

    replies = client.parse_batch_reply(
        dispatcher().dispatch(arrived).serialize())

    assert isinstance(replies[0], XMLRPCSuccessResponse)
    assert replies[0].result == 10
    assert isinstance(replies[1], XMLRPCErrorResponse)
    assert replies[1].error == 'Method not found'
    assert isinstance(replies[2], XMLRPCErrorResponse)
    assert 'kaboom' in replies[2].error


def test_a_batch_reply_is_not_mistaken_for_a_single_one():
    """And the reverse, which is why the caller has to say: parse_reply()
    reads the same bytes as an ordinary reply returning an array."""
    client, server = protocol(), protocol()
    arrived = server.parse_request(
        batch_of(client, [('add', [7, 3])]).serialize())
    wire = dispatcher().dispatch(arrived).serialize()

    single = client.parse_reply(wire)
    assert isinstance(single, XMLRPCSuccessResponse)
    assert single.result == [[10]], "an array, because nothing said otherwise"

    assert [r.result for r in client.parse_batch_reply(wire)] == [10]


def test_an_empty_batch():
    client, server = protocol(), protocol()
    with pytest.raises(Exception):
        client.parse_batch_reply(
            dispatcher().dispatch(
                server.parse_request(
                    batch_of(client, []).serialize())).serialize())


# ------------------------------------------------ against the stdlib --

@pytest.fixture
def tinyrpc_server():
    transport = HttpServerTransport((HOST, 0), content_type='text/xml')
    executor = ThreadPoolExecutor(max_workers=6)
    server = RPCServerExecutor(transport, protocol(), dispatcher(), executor)
    server.start()
    yield transport.endpoint[1]
    server.stop()
    executor.shutdown(wait=False)


def test_the_stdlib_multicall_client_can_call_us(tinyrpc_server):
    """The point of implementing the convention rather than something of our
    own: anything that already speaks XML-RPC can batch against us."""
    proxy = xmlrpc.client.ServerProxy('http://%s:%d/' % (HOST, tinyrpc_server),
                                      allow_none=True)
    multicall = xmlrpc.client.MultiCall(proxy)
    multicall.add(7, 3)
    multicall.sub(7, 3)
    multicall.boom()

    results = []
    iterator = iter(multicall())
    for _ in range(3):
        try:
            results.append(next(iterator))
        except xmlrpc.client.Fault as fault:
            results.append(fault.faultString)

    assert results[:2] == [10, 4]
    assert 'kaboom' in results[2]


@pytest.fixture
def stdlib_server():
    class Threading(ThreadingMixIn, SimpleXMLRPCServer):
        daemon_threads = True
        allow_reuse_address = True

    server = Threading((HOST, 0), allow_none=True, logRequests=False)
    server.register_multicall_functions()
    server.register_function(add, 'add')
    server.register_function(sub, 'sub')
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def test_we_can_batch_against_a_stdlib_server(stdlib_server):
    client = RPCClient(protocol(), HttpClientTransport(
        'http://%s:%d/' % (HOST, stdlib_server), content_type='text/xml'))

    replies = client.batch_call([('add', [7, 3], None),
                                 ('sub', [7, 3], None)])
    assert [r.result for r in replies] == [10, 4]


def test_a_server_without_multicall_still_refuses_it(stdlib_server):
    """Which is what an un-upgraded Gen2 server is: ro_XMLRPC never called
    register_multicall_functions(), so batching against one is not something
    that used to work."""
    class Threading(ThreadingMixIn, SimpleXMLRPCServer):
        daemon_threads = True
        allow_reuse_address = True

    plain = Threading((HOST, 0), allow_none=True, logRequests=False)
    plain.register_function(add, 'add')
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    try:
        client = RPCClient(protocol(), HttpClientTransport(
            'http://%s:%d/' % (HOST, plain.server_address[1]),
            content_type='text/xml'))
        with pytest.raises(Exception):
            client.batch_call([('add', [7, 3], None)])
    finally:
        plain.shutdown()
        plain.server_close()
