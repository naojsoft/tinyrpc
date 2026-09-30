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


# --------------------------------------------------------------- numpy --

def _has_working_msgpack_numpy():
    """msgpack-numpy hands the packer an ndarray's memoryview, and msgpack's
    pure-Python fallback writes the element count where the byte count
    belongs.  Only the C extension gets this right."""
    try:
        import msgpack_numpy
        import numpy as np
    except ImportError:
        return False
    a = np.arange(12, dtype='f4').reshape(3, 4)
    try:
        return np.array_equal(
            msgpack_numpy.unpackb(msgpack_numpy.packb(a, use_bin_type=True),
                                  raw=False), a)
    except Exception:
        return False


needs_numpy = pytest.mark.skipif(
    not _has_working_msgpack_numpy(),
    reason='needs msgpack-numpy on msgpack with its C extension')


@needs_numpy
def test_an_array_survives_the_trip():
    import numpy as np
    client = FlexRPCProtocol('msgpack-numpy')
    server = FlexRPCProtocol('json')          # its own preference is irrelevant

    a = np.arange(12, dtype='f4').reshape(3, 4)
    _request, arrived = roundtrip(client, server, 'put', (a,))

    assert np.array_equal(arrived.args[0], a)
    assert arrived.args[0].dtype == a.dtype, "dtype must survive, not just values"


@needs_numpy
def test_an_array_comes_back_too():
    import numpy as np
    client = FlexRPCProtocol('msgpack-numpy')
    server = FlexRPCProtocol('msgpack-numpy')

    a = np.linspace(0, 1, 64).reshape(8, 8)
    _request, arrived = roundtrip(client, server, 'scale', (a,))
    reply = client.parse_reply(arrived.respond(arrived.args[0] * 2).serialize())
    assert np.allclose(reply.result, a * 2)


@needs_numpy
def test_an_array_is_carried_as_a_buffer_not_a_list_of_numbers():
    import numpy as np
    a = np.zeros(1000, dtype='f8')
    packed = FlexRPCProtocol('msgpack-numpy').create_request('put', [a])
    assert len(packed.serialize()) < 8500, "should be the raw 8000 bytes plus a little"


def test_a_peer_without_numpy_encoding_is_told_so_not_left_guessing():
    """The header names the encoding, so an array does not arrive quietly
    decoded into something that is not one."""
    from tinyrpc.serializers import SERIALIZER_MSGPACK_NUMPY, serializer_by_id
    assert serializer_by_id(SERIALIZER_MSGPACK_NUMPY).name == 'msgpack-numpy'

    protocol = FlexRPCProtocol('json')
    wire = bytearray(protocol.create_request('put', [[1, 2]]).serialize())
    wire[4] = 200                                 # an id nobody has
    with pytest.raises(RPCError) as excinfo:
        protocol.parse_request(bytes(wire))
    assert 'no serializer' in str(excinfo.value)


def test_a_site_can_register_its_own_encoding():
    from tinyrpc import serializers
    calls = []

    def dumps(obj):
        calls.append('dumps')
        return repr(obj).encode()

    def loads(data):
        import ast
        return ast.literal_eval(data.decode())

    serializers.register('reprs', serializers.SERIALIZER_LOCAL, dumps, loads)
    try:
        client = FlexRPCProtocol('reprs')
        _request, arrived = roundtrip(client, FlexRPCProtocol('json'))
        assert arrived.args == ['hi']
        assert calls, "the registered encoder should have been used"
    finally:
        del serializers.SERIALIZERS['reprs']
        del serializers._BY_ID[serializers.SERIALIZER_LOCAL]


def test_an_id_that_is_already_spoken_for():
    from tinyrpc import serializers
    with pytest.raises(ValueError) as excinfo:
        serializers.register('mine', serializers.SERIALIZER_JSON,
                             lambda o: b'', lambda d: None)
    assert 'json' in str(excinfo.value)


def test_an_id_that_does_not_fit_in_the_header():
    from tinyrpc import serializers
    with pytest.raises(ValueError):
        serializers.register('mine', 256, lambda o: b'', lambda d: None)


# ------------------------------------------------- oversized integers --

@pytest.mark.parametrize('encoding', ['json', 'msgpack'])
def test_an_integer_too_big_for_msgpack_still_crosses(encoding):
    """An encoding is meant to be a choice about bytes, not about what a
    program may send.  msgpack stops at 64 bits where json does not, so
    without help the choice would change the semantics."""
    big = 2 ** 70
    client = FlexRPCProtocol(encoding)
    _request, arrived = roundtrip(client, FlexRPCProtocol('json'),
                                  'store', ({'n': big, 'neg': -big},))
    assert arrived.args[0] == {'n': big, 'neg': -big}


def test_something_msgpack_genuinely_cannot_carry_is_still_an_error():
    """The big-integer hook must not become a silent catch-all."""
    client = FlexRPCProtocol('msgpack')
    with pytest.raises(TypeError):
        client.create_request('store', [object()]).serialize()


@needs_numpy
def test_arrays_and_oversized_integers_together():
    import numpy as np
    big = 2 ** 70
    a = np.arange(6, dtype='f8')
    client = FlexRPCProtocol('msgpack-numpy')
    _request, arrived = roundtrip(client, FlexRPCProtocol('msgpack-numpy'),
                                  'store', ({'a': a, 'n': big},))
    assert np.array_equal(arrived.args[0]['a'], a)
    assert arrived.args[0]['n'] == big


# ------------------------------------------- answering under their key --

def test_a_caller_that_holds_only_its_own_key_cannot_check_the_reply():
    """Stated because it is the constraint that shapes the shared-secret
    mapping: a service signs as itself, so a caller must hold the service's
    key to verify what comes back."""
    service = FlexRPCProtocol(framing=signed('status'))   # holds both keys
    caller = FlexRPCProtocol(framing=Framing(
        layers=[Signature({'taskmgr': KEY_B})]))          # holds only its own

    arrived = service.parse_request(caller.create_request('echo').serialize())
    assert arrived.principal == 'taskmgr'

    with pytest.raises(InvalidReplyError) as excinfo:
        caller.parse_reply(arrived.respond('HI').serialize())
    assert 'status' in str(excinfo.value)


def test_answering_under_the_caller_key_is_available_but_deliberate():
    """Right where the key is a secret both ends share, since there it names
    the secret and not the sender.  Never automatic, because with keys that
    identify senders it would be a lie about who answered."""
    service = FlexRPCProtocol(framing=signed('status'))
    caller = FlexRPCProtocol(framing=Framing(
        layers=[Signature({'taskmgr': KEY_B})]))

    arrived = service.parse_request(caller.create_request('echo').serialize())
    assert arrived.sign_as is None, "not done behind anyone's back"

    reply = arrived.respond('HI')
    reply.sign_as = arrived.signed_as
    assert caller.parse_reply(reply.serialize()).result == 'HI'


def test_an_error_reply_can_be_signed_the_same_way():
    service = FlexRPCProtocol(framing=signed('status'))
    caller = FlexRPCProtocol(framing=Framing(
        layers=[Signature({'taskmgr': KEY_B})]))
    caller.raises_errors = False

    arrived = service.parse_request(caller.create_request('boom').serialize())
    failed = arrived.error_respond(ValueError('no'))
    failed.sign_as = arrived.signed_as
    assert caller.parse_reply(failed.serialize()).code == ERROR_APPLICATION


def test_the_key_that_verified_is_recorded_even_when_several_share_a_name():
    """Two keys for one principal -- a rotation -- and it still says which
    one was actually used, which is what revoking one needs."""
    table = {'status-2024': (KEY, 'status'), 'status-2025': (KEY_B, 'status')}
    service = FlexRPCProtocol(framing=Framing(
        layers=[Signature(table, sign_as='status-2025')],
        require=FLAG_SIGNED))
    old = FlexRPCProtocol(framing=Framing(
        layers=[Signature({'status-2024': (KEY, 'status')})]))

    arrived = service.parse_request(old.create_request('echo').serialize())
    assert arrived.principal == 'status'
    assert arrived.signed_as == 'status-2024'


def test_signing_as_a_key_this_end_does_not_hold():
    from tinyrpc.framing import FramingError
    f = Framing(layers=[Signature({'status': KEY})])
    with pytest.raises(FramingError) as excinfo:
        f.wrap(b'x', sign_as='taskmgr')
    assert 'no key for' in str(excinfo.value)
