#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""FlexRPC: one envelope, a chosen encoding, and an identity that travelled.

The three things this protocol is for are the three things tested hardest:
that a reply comes back in the encoding its request arrived in, that a
verified signature reaches the server as a principal while a carried
password does not, and that a receiver can refuse a peer which declined the
protection it requires.
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from tinyrpc.client import RPCClient
from tinyrpc.dispatch import RPCDispatcher
from tinyrpc.exc import InvalidReplyError, RPCError
from tinyrpc.framing import FLAG_CREDENTIALS, FLAG_SIGNED, Framing
from tinyrpc.layers import Credentials, Signature
from tinyrpc.protocols.flexrpc import (BODY_VERSION, ERROR_APPLICATION,
                                       ERROR_METHOD_NOT_FOUND, ERROR_REFUSED,
                                       FlexRPCError, FlexRPCProtocol,
                                       require_principal)
from tinyrpc.serializers import SERIALIZER_JSON, SERIALIZER_MSGPACK
from tinyrpc.server.executor import RPCServerExecutor
from tinyrpc.transports.tcp import (ConnectionlessTcpClientTransport,
                                    ConnectionlessTcpServerTransport)

KEY = b'k' * 32
KEY_B = b'b' * 32
HOST = '127.0.0.1'


def signed(sign_as='status', keys=None, **kw):
    keys = keys or {'status': KEY, 'taskmgr': KEY_B}
    return Framing(layers=[Signature(keys, sign_as=sign_as, **kw)])


def roundtrip(client, server, method='echo', args=('hi',), kwargs=None):
    request = client.create_request(method, list(args), kwargs or {})
    arrived = server.parse_request(request.serialize())
    return request, arrived


# --------------------------------------------------------- the basics --

def test_a_call_and_its_reply():
    client = FlexRPCProtocol()
    server = FlexRPCProtocol()

    request, arrived = roundtrip(client, server)
    assert arrived.method == 'echo'
    assert arrived.args == ['hi']

    reply = client.parse_reply(arrived.respond('HI').serialize())
    assert reply.result == 'HI'
    assert reply.unique_id == request.unique_id


def test_keyword_arguments_are_carried():
    """XML-RPC cannot do this at all, which is most of why it is here."""
    client = FlexRPCProtocol()
    _request, arrived = roundtrip(client, FlexRPCProtocol(), 'move',
                                  ('az',), {'degrees': 3.5, 'wait': True})
    assert arrived.args == ['az']
    assert arrived.kwargs == {'degrees': 3.5, 'wait': True}


def test_a_one_way_call_wants_no_reply():
    client = FlexRPCProtocol()
    request = client.create_request('log', ['started'], one_way=True)
    arrived = FlexRPCProtocol().parse_request(request.serialize())

    assert arrived.one_way
    assert arrived.respond('ignored') is None
    assert arrived.error_respond(ValueError('nor this')) is None


def test_several_calls_can_be_in_flight():
    """Replies carry the id they answer, which is what a multiplexing client
    needs and what XML-RPC cannot offer."""
    client = FlexRPCProtocol()
    server = FlexRPCProtocol()
    assert client.supports_reply_correlation

    first = client.create_request('a')
    second = client.create_request('b')
    assert first.unique_id != second.unique_id

    # Answered in the other order, as a busy server would.
    replies = [server.parse_request(r.serialize()).respond(r.method)
               for r in (second, first)]
    parsed = [client.parse_reply(r.serialize()) for r in replies]

    assert {p.unique_id: p.result for p in parsed} == {
        first.unique_id: 'a', second.unique_id: 'b'}


# ------------------------------------------------------ the encoding --

def test_a_reply_comes_back_in_the_encoding_it_was_asked_in():
    """Neither end is configured with the other's preference; the envelope
    says which was used, so a server just answers in kind."""
    client = FlexRPCProtocol('json')
    server = FlexRPCProtocol('msgpack')

    _request, arrived = roundtrip(client, server)
    assert arrived.serializer_id == SERIALIZER_JSON

    reply = arrived.respond('HI')
    assert reply.serializer_id == SERIALIZER_JSON
    assert b'"result"' in reply.serialize(), "should be json on the wire"
    assert client.parse_reply(reply.serialize()).result == 'HI'


def test_the_other_direction_too():
    client = FlexRPCProtocol('msgpack')
    server = FlexRPCProtocol('json')
    _request, arrived = roundtrip(client, server)
    assert arrived.serializer_id == SERIALIZER_MSGPACK
    assert client.parse_reply(arrived.respond('HI').serialize()).result == 'HI'


def test_msgpack_is_the_smaller_of_the_two():
    body = {'frames': list(range(200))}
    packed = FlexRPCProtocol('msgpack').create_request('put', [body])
    text = FlexRPCProtocol('json').create_request('put', [body])
    assert len(packed.serialize()) < len(text.serialize())


def test_an_unknown_serializer_is_refused():
    with pytest.raises(ValueError) as excinfo:
        FlexRPCProtocol('yaml')
    assert 'yaml' in str(excinfo.value)


def test_a_body_encoded_with_something_we_do_not_have():
    client = FlexRPCProtocol()
    wire = bytearray(client.create_request('echo').serialize())
    wire[4] = 99                                  # the serializer byte
    with pytest.raises(RPCError):
        FlexRPCProtocol().parse_request(bytes(wire))


# ------------------------------------------------------- one envelope --

def test_the_body_carries_no_version_of_its_own():
    """The header versions the body, so there is no second envelope inside
    the first -- which is the whole point of merging them."""
    from tinyrpc.serializers import get_serializer
    wire = FlexRPCProtocol('json').create_request('echo', ['hi']).serialize()
    body = get_serializer('json').loads(wire[10:])

    assert set(body) == {'type', 'id', 'method', 'args', 'kwargs'}
    assert wire[5] == BODY_VERSION, "the version is a header byte"


def test_a_body_shape_from_the_future_is_refused_before_it_is_read():
    client = FlexRPCProtocol()
    wire = bytearray(client.create_request('echo').serialize())
    wire[5] = BODY_VERSION + 1
    with pytest.raises(RPCError) as excinfo:
        FlexRPCProtocol().parse_request(bytes(wire))
    assert 'body version' in str(excinfo.value)


# ------------------------------------------------------------- errors --

def test_a_missing_method_is_reported_with_the_usual_code():
    from tinyrpc.exc import MethodNotFoundError
    client = FlexRPCProtocol()
    _request, arrived = roundtrip(client, FlexRPCProtocol(), 'nope')

    failed = arrived.error_respond(MethodNotFoundError('nope'))
    reply = client.parse_reply(failed.serialize())
    assert reply.code == ERROR_METHOD_NOT_FOUND


def test_a_method_that_raised_names_the_exception_type():
    """Without a traceback it is often the only clue what went wrong."""
    client = FlexRPCProtocol()
    _request, arrived = roundtrip(client, FlexRPCProtocol())

    reply = client.parse_reply(
        arrived.error_respond(KeyError('shutter')).serialize())
    assert reply.code == ERROR_APPLICATION
    assert 'KeyError' in reply.error


def test_an_error_reply_becomes_an_exception():
    client = FlexRPCProtocol()
    _request, arrived = roundtrip(client, FlexRPCProtocol())
    reply = client.parse_reply(
        arrived.error_respond(ValueError('bad')).serialize())

    with pytest.raises(FlexRPCError) as excinfo:
        client.raise_error(reply)
    assert excinfo.value.code == ERROR_APPLICATION


def test_an_error_is_a_message_type_not_a_value():
    """A result that happens to look like an error must not be mistaken for
    one, so they are different messages."""
    client = FlexRPCProtocol()
    _request, arrived = roundtrip(client, FlexRPCProtocol())
    reply = client.parse_reply(
        arrived.respond({'code': -32500, 'message': 'not really'}).serialize())
    assert reply.result == {'code': -32500, 'message': 'not really'}
    assert not hasattr(reply, 'code') or reply.result is not None


def test_something_that_is_not_a_reply():
    client = FlexRPCProtocol()
    request = client.create_request('echo')
    with pytest.raises(InvalidReplyError):
        client.parse_reply(request.serialize())


def test_a_request_naming_no_method():
    protocol = FlexRPCProtocol('json')
    from tinyrpc.serializers import get_serializer
    body = get_serializer('json').dumps({'type': 'request', 'id': 1})
    wire = protocol.framing.wrap(body, serializer_id=SERIALIZER_JSON)
    with pytest.raises(RPCError) as excinfo:
        protocol.parse_request(wire)
    assert 'no method' in str(excinfo.value)


# --------------------------------------------------- proven vs claimed --

def test_a_verified_signature_arrives_as_a_principal():
    client = FlexRPCProtocol(framing=signed('status'))
    server = FlexRPCProtocol(framing=signed('taskmgr'))

    _request, arrived = roundtrip(client, server)
    assert arrived.principal == 'status'
    assert arrived.credentials is None


def test_a_password_arrives_as_a_claim_and_nothing_more():
    client = FlexRPCProtocol(credentials=Credentials('bob', 'hunter2'))
    server = FlexRPCProtocol()

    _request, arrived = roundtrip(client, server)
    assert arrived.credentials.username == 'bob'
    assert arrived.principal is None, "nothing checked that password"


def test_both_at_once_stay_apart():
    client = FlexRPCProtocol(framing=signed('status'),
                             credentials=Credentials('bob', 'hunter2'))
    server = FlexRPCProtocol(framing=signed('taskmgr'))

    _request, arrived = roundtrip(client, server)
    assert arrived.principal == 'status'
    assert arrived.credentials.username == 'bob'


def test_a_forged_request_is_refused_and_says_so():
    client = FlexRPCProtocol(framing=Framing(layers=[Signature(
        {'status': b'wrong key' + b'-' * 23})]))
    server = FlexRPCProtocol(framing=signed('taskmgr'))

    with pytest.raises(RPCError) as excinfo:
        server.parse_request(client.create_request('echo').serialize())

    reply = excinfo.value.error_respond()
    assert reply.code == ERROR_REFUSED
    assert reply.unique_id is None, \
        "a message that failed the envelope carries no id worth echoing"


def test_a_peer_cannot_decline_the_protection_this_end_requires():
    """The reason a receiver states requirements at all: without it a sender
    simply sends an unsigned message and walks past the check."""
    unsigned = FlexRPCProtocol()
    server = FlexRPCProtocol(framing=Framing(layers=[Signature({'s': KEY})],
                                             require=FLAG_SIGNED))

    with pytest.raises(RPCError) as excinfo:
        server.parse_request(unsigned.create_request('echo').serialize())
    assert excinfo.value.error_respond().code == ERROR_REFUSED


def test_the_reply_does_not_carry_the_caller_password_back():
    client = FlexRPCProtocol(credentials=Credentials('bob', 'hunter2'))
    server = FlexRPCProtocol()

    _request, arrived = roundtrip(client, server)
    wire = arrived.respond('HI').serialize()

    assert b'hunter2' not in wire
    assert not wire[3] & FLAG_CREDENTIALS


def test_a_relayed_request_borrows_nobody_password():
    """Re-sending a request that arrived must not attach the caller's
    password, nor quietly substitute this service's own."""
    client = FlexRPCProtocol(credentials=Credentials('bob', 'hunter2'))
    relay = FlexRPCProtocol(credentials=Credentials('relay', 'relaypw'))

    _request, arrived = roundtrip(client, relay)
    onward = arrived.serialize()

    assert b'hunter2' not in onward, "not the caller's"
    assert b'relaypw' not in onward, "nor ours, unasked"
    assert not onward[3] & FLAG_CREDENTIALS


def test_a_reply_is_signed_by_the_service_that_sent_it():
    """So a client can tell it was answered by who it asked."""
    client = FlexRPCProtocol(framing=signed('status'))
    server = FlexRPCProtocol(framing=signed('taskmgr'))

    _request, arrived = roundtrip(client, server)
    reply = client.parse_reply(arrived.respond('HI').serialize())
    assert reply.principal == 'taskmgr'


# --------------------------------------------------- require_principal --

def test_require_principal_admits_the_named():
    client = FlexRPCProtocol(framing=signed('status'))
    server = FlexRPCProtocol(framing=signed('taskmgr'))
    _request, arrived = roundtrip(client, server)

    require_principal('status', 'gateway')(None, arrived)


def test_require_principal_refuses_anyone_else():
    client = FlexRPCProtocol(framing=signed('taskmgr'))
    server = FlexRPCProtocol(framing=signed('status'))
    _request, arrived = roundtrip(client, server)

    with pytest.raises(PermissionError) as excinfo:
        require_principal('status')(None, arrived)
    assert 'taskmgr' in str(excinfo.value)


def test_require_principal_is_not_fooled_by_a_claimed_name():
    """The whole point of looking at the principal: a caller can put any
    name it likes in the credentials."""
    client = FlexRPCProtocol(credentials=Credentials('status', 'anything'))
    server = FlexRPCProtocol()
    _request, arrived = roundtrip(client, server)

    with pytest.raises(PermissionError) as excinfo:
        require_principal('status')(None, arrived)
    assert 'signed' in str(excinfo.value)


# -------------------------------------------------------- end to end --

class Service:
    def echo(self, value, loud=False):
        return value.upper() if loud else value

    def explode(self):
        raise RuntimeError('the dome is stuck')


def serve(protocol_for_server, authenticator=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, 0))
    sock.listen(16)

    served = Service()
    dispatcher = RPCDispatcher()
    dispatcher.add_method(served.echo, 'echo')
    dispatcher.add_method(served.explode, 'explode')
    transport = ConnectionlessTcpServerTransport(sock, poll_timeout=0.1)
    # One worker for the serve loop itself, the rest for handlers.
    executor = ThreadPoolExecutor(max_workers=5)
    server = RPCServerExecutor(transport, protocol_for_server, dispatcher,
                               executor, ev_quit=threading.Event())
    server.authenticator = authenticator
    server.start()
    return server, executor, sock.getsockname()


def test_a_real_call_over_a_real_socket():
    protocol = FlexRPCProtocol(framing=signed('taskmgr'))
    server, executor, endpoint = serve(protocol)
    try:
        client = RPCClient(FlexRPCProtocol(framing=signed('status')),
                           ConnectionlessTcpClientTransport(endpoint,
                                                            timeout=10))
        proxy = client.get_proxy()
        assert proxy.echo('hi') == 'hi'
        assert proxy.echo('hi', loud=True) == 'HI', "kwargs over the wire"
    finally:
        server.stop()
        executor.shutdown(wait=False)


def test_an_authenticator_sees_the_principal_over_a_real_socket():
    protocol = FlexRPCProtocol(framing=signed('taskmgr'))
    seen = []

    def watch(context, request):
        seen.append(request.principal)
        require_principal('status')(context, request)

    server, executor, endpoint = serve(protocol, authenticator=watch)
    try:
        client = RPCClient(FlexRPCProtocol(framing=signed('status')),
                           ConnectionlessTcpClientTransport(endpoint,
                                                            timeout=10))
        assert client.get_proxy().echo('hi') == 'hi'
        assert seen == ['status']
    finally:
        server.stop()
        executor.shutdown(wait=False)


def test_a_stranger_is_turned_away_over_a_real_socket():
    protocol = FlexRPCProtocol(framing=signed('taskmgr'))
    server, executor, endpoint = serve(protocol,
                             authenticator=require_principal('gateway'))
    try:
        client = RPCClient(FlexRPCProtocol(framing=signed('status')),
                           ConnectionlessTcpClientTransport(endpoint,
                                                            timeout=10))
        with pytest.raises(FlexRPCError) as excinfo:
            client.get_proxy().echo('hi')
        assert 'may not call this service' in str(excinfo.value)
        assert excinfo.value.code == ERROR_REFUSED, \
            "a refusal is not an application error; the caller can tell"
    finally:
        server.stop()
        executor.shutdown(wait=False)


def test_a_method_that_raises_comes_back_as_an_error():
    protocol = FlexRPCProtocol(framing=signed('taskmgr'))
    server, executor, endpoint = serve(protocol)
    try:
        client = RPCClient(FlexRPCProtocol(framing=signed('status')),
                           ConnectionlessTcpClientTransport(endpoint,
                                                            timeout=10))
        with pytest.raises(FlexRPCError) as excinfo:
            client.get_proxy().explode()
        assert 'dome is stuck' in str(excinfo.value)
    finally:
        server.stop()
        executor.shutdown(wait=False)
