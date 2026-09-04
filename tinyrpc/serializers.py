#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""How a protocol's body is turned into bytes, as a choice rather than a given.

XML-RPC, JSON-RPC and msgpack-RPC each fix their encoding: the specification
*is* the encoding.  A protocol built on :py:mod:`tinyrpc.framing` need not,
because the envelope records which serializer was used in a header byte, so
the far end can decode a message without being told in advance and can
answer in the encoding it was addressed in.

The ids are what travels, so they are fixed forever; the names are for
people.  Zero is deliberately unassigned, so that a header from a protocol
that does not care carries no accidental meaning.
"""

import json
from typing import Any, Callable, Dict, NamedTuple

#: Reserved: a message whose protocol does not use this field.
SERIALIZER_NONE = 0
SERIALIZER_JSON = 1
SERIALIZER_MSGPACK = 2
SERIALIZER_MSGPACK_NUMPY = 3

#: Ids from here up are never assigned by tinyrpc, so a site can
#: :py:func:`register` its own encoding without colliding with a later one.
SERIALIZER_LOCAL = 128


class Serializer(NamedTuple):
    """One way of turning a body into bytes and back."""

    id: int
    name: str
    dumps: Callable[[Any], bytes]
    loads: Callable[[bytes], Any]


def _json_dumps(obj: Any) -> bytes:
    return json.dumps(obj).encode('utf-8')


def _json_loads(data: bytes) -> Any:
    return json.loads(data.decode('utf-8'))


#: msgpack has no integer wider than 64 bits.  json and XML both do, so
#: without this the choice of encoding would quietly change what a program
#: can send -- a value that crosses as json raising OverflowError as
#: msgpack.  Oversized integers therefore travel as an extension type
#: holding their decimal text.
#:
#: The code is 42 because that is what Gen2's own packer has always used,
#: and the same values pass through both.
MSGPACK_EXT_BIGINT = 42


def _msgpack_bigint(obj: Any) -> Any:
    """Encode what msgpack itself cannot, and only that."""
    import msgpack
    if isinstance(obj, int):
        return msgpack.ExtType(MSGPACK_EXT_BIGINT,
                               str(obj).encode('ascii'))
    raise TypeError('cannot serialize %r' % (obj,))


def _msgpack_ext(code: int, data: bytes) -> Any:
    import msgpack
    if code == MSGPACK_EXT_BIGINT:
        return int(data)
    return msgpack.ExtType(code, data)


def _msgpack_dumps(obj: Any) -> bytes:
    import msgpack
    return msgpack.packb(obj, default=_msgpack_bigint, use_bin_type=True)


def _msgpack_loads(data: bytes) -> Any:
    import msgpack
    return msgpack.unpackb(data, ext_hook=_msgpack_ext, raw=False)


def _msgpack_numpy_dumps(obj: Any) -> bytes:
    import msgpack_numpy
    # msgpack-numpy chains whatever default it is given after its own, so
    # arrays and oversized integers both survive.
    return msgpack_numpy.packb(obj, default=_msgpack_bigint,
                               use_bin_type=True)


def _msgpack_numpy_loads(data: bytes) -> Any:
    import msgpack_numpy
    # msgpack-numpy carries arrays as mappings and reads them with an
    # object_hook, so the extension hook is free for oversized integers.
    return msgpack_numpy.unpackb(data, ext_hook=_msgpack_ext, raw=False)


#: Everything that can be asked for by name.  Note what is absent: pickle.
#: Unpickling runs whatever it is sent, which is not a property to offer a
#: peer over a socket, however trusted the network is meant to be.
#:
#: .. warning::
#:
#:     msgpack is compact and fast *when its C extension is installed*, and
#:     it silently falls back to a pure-Python implementation when it is
#:     not.  The fallback is roughly ten times slower than :py:mod:`json`
#:     -- 187us to pack what json writes in 32us -- so a deployment that
#:     picks msgpack for speed and gets the fallback has chosen the slowest
#:     option available to it.  ``python -c "import msgpack;
#:     print(msgpack._cmsgpack)"`` says which one is present.
SERIALIZERS: Dict[str, Serializer] = {
    'json': Serializer(SERIALIZER_JSON, 'json', _json_dumps, _json_loads),
    'msgpack': Serializer(SERIALIZER_MSGPACK, 'msgpack',
                          _msgpack_dumps, _msgpack_loads),
    # Arrays and numpy scalars, as msgpack extension types: a buffer, a
    # dtype and a shape rather than a list of numbers.  It has an id of its
    # own rather than patching msgpack globally, so the header says which
    # encoding was used and a peer that lacks msgpack-numpy is told exactly
    # that instead of decoding an array into dicts.
    'msgpack-numpy': Serializer(SERIALIZER_MSGPACK_NUMPY, 'msgpack-numpy',
                                _msgpack_numpy_dumps, _msgpack_numpy_loads),
}

_BY_ID: Dict[int, Serializer] = {s.id: s for s in SERIALIZERS.values()}


def register(name: str, id: int, dumps: Callable[[Any], bytes],
             loads: Callable[[bytes], Any]) -> Serializer:
    """Add an encoding of your own.

    The id is what travels, so both ends must agree on it and it must not
    change once anything has spoken it.  Use :py:data:`SERIALIZER_LOCAL` or
    above, which tinyrpc will never assign.
    """
    if not 0 < id < 256:
        raise ValueError('a serializer id is one byte, and 0 is reserved')
    existing = _BY_ID.get(id)
    if existing is not None and existing.name != name:
        raise ValueError("id %d is already %s's" % (id, existing.name))

    serializer = Serializer(id, name, dumps, loads)
    SERIALIZERS[name] = serializer
    _BY_ID[id] = serializer
    return serializer


def get_serializer(name: str) -> Serializer:
    """Look one up by name, checking now that it can actually be used."""
    try:
        serializer = SERIALIZERS[name]
    except KeyError:
        raise ValueError("unknown serializer '%s'; there is %s"
                         % (name, ', '.join(sorted(SERIALIZERS)))) from None
    # Better to find a missing dependency here than on the first call.
    serializer.dumps({})
    return serializer


def serializer_by_id(serializer_id: int) -> Serializer:
    """Look one up by the id carried in a framing header."""
    try:
        return _BY_ID[serializer_id]
    except KeyError:
        raise ValueError('no serializer has id %r' % (serializer_id,)) from None
