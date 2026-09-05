#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""One envelope for the things that happen to a message's bytes.

Compression, encryption and authentication are the same shape: each
transforms the byte stream between the protocol and the transport, and each
needs a little metadata carried alongside so the far end can undo it.  So
they share one header rather than each inventing a wrapper.

The header is fixed and binary::

    magic(2) version(1) flags(1) serializer(1) protocol(1) length(4)

Ten bytes, packed with :py:mod:`struct`.  The flags say which optional
sections follow; when nothing is enabled the flags are zero, the header is
all there is, and the body is the payload verbatim -- so an unsecured
message pays for one ``struct.pack`` and one ``struct.unpack``, about 0.2us
the pair.  A JSON header of the kind this replaces costs 2.7us and 51 bytes.

:py:class:`Credentials` lives here too.  It is not a :py:class:`Layer` --
it transforms nothing, it is just carried -- but the section it travels in
is part of this header, so this is where it belongs.

Layers are applied outward on the way out and unwound on the way in::

    payload -> compress -> encrypt -> sign -> header + sections + body

Compress before encrypt, because ciphertext does not compress; sign last, so
what is verified is what arrived.

.. warning::

    A receiver must not simply do whatever the header asks.  A sender that
    declares no encryption and no credentials would otherwise walk past both.
    :py:class:`Framing` therefore takes a *required* set, and refuses a
    message that does not meet it, whatever its flags say.
"""

import hmac
import struct
from typing import (Any, Dict, Optional, Sequence, Tuple,
                    Union)

MAGIC = b'FX'
VERSION = 1

#: ``magic, version, flags, serializer, protocol, length``
HEADER = '!2sBBBBI'
HEADER_LEN = struct.calcsize(HEADER)

# Flag bits, one per optional section.  A section is present only when its
# flag is set, and sections appear in this order.
FLAG_COMPRESSED = 0x01
FLAG_ENCRYPTED = 0x02
FLAG_SIGNED = 0x04
FLAG_CREDENTIALS = 0x08

#: Sections, in the order they are written.  Each is a 2-byte length
#: followed by that many bytes.
SECTION_ORDER = [
    (FLAG_CREDENTIALS, 'credentials'),
    (FLAG_ENCRYPTED, 'nonce'),
    (FLAG_SIGNED, 'signature'),
]

_SECTION = '!H'
_SECTION_LEN = struct.calcsize(_SECTION)


class FramingError(Exception):
    """A message could not be framed or unframed."""


class UnsupportedVersion(FramingError):
    """The message announces an envelope version this build does not know."""


class PolicyError(FramingError):
    """The message did not meet what the receiver requires.

    Raised when a peer omits a layer this end insists on -- which is the
    only thing standing between a pluggable security layer and a sender that
    simply declares it applied nothing.
    """


class Credentials:
    """A name and a secret, carried in the header's credentials section.

    Not a :py:class:`~tinyrpc.framing.Layer`: it transforms nothing, it is
    just carried.  A protocol passes it to
    :py:meth:`~tinyrpc.framing.Framing.wrap` and reads it back out of the
    metadata on the other side.

    .. warning::

        The secret goes on the wire as it is.  Over a connection nothing else
        protects, anyone who can see the traffic can reuse it.  Prefer
        :py:class:`Signature`, or put this inside :py:class:`Encrypt`.
    """

    __slots__ = ('username', 'password')

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password

    def encode(self) -> bytes:
        return b'\x00'.join([self.username.encode('utf-8'),
                             self.password.encode('utf-8')])

    @classmethod
    def decode(cls, blob: bytes) -> 'Credentials':
        try:
            username, password = blob.split(b'\x00', 1)
        except ValueError:
            raise FramingError('malformed credentials') from None
        return cls(username.decode('utf-8'), password.decode('utf-8'))

    def __eq__(self, other: Any) -> bool:
        return (isinstance(other, Credentials) and
                self.username == other.username and
                hmac.compare_digest(self.password, other.password))

    def __repr__(self) -> str:
        return "<Credentials %s>" % (self.username,)


class Unwrapped:
    """What came out of an envelope, and how much of it can be believed.

    The distinction this draws is the point of the class.  A signature that
    verified is *proof*: the framing checked it, and a message that failed
    never got this far.  Credentials are only ever a *claim* -- the sender
    said who it was, and nothing here has tested that.  Handing both to a
    caller as "auth" invites treating the second like the first, so they are
    named apart and only a layer can set :py:attr:`principal`.

    .. py:attribute:: payload

        The message, with every layer undone.

    .. py:attribute:: principal

        Who the sender is *proven* to be, or ``None``.  Set only by a layer
        that verified it; nothing a sender writes can reach this.

    .. py:attribute:: signed_as

        The id of the key that actually verified, or ``None``.  Where
        several keys map to one principal -- a rotation, an alias -- this
        says which was used, which is what a revocation or an audit trail
        needs.  It is also what to sign a reply with, so an answer goes back
        under the key the caller demonstrably holds.

    .. py:attribute:: claimed_credentials

        What the sender asserted about itself, unverified, or ``None``.
        Whoever reads this is responsible for checking it.

    .. py:attribute:: serializer_id
    .. py:attribute:: protocol_id

        The two bytes the protocol stamped on the way out.  Read them to
        answer in the encoding you were addressed in, and to refuse a body
        shape you do not know before trying to read it.
    """

    __slots__ = ('payload', 'serializer_id', 'protocol_id', 'flags',
                 'principal', 'signed_as', 'claimed_credentials', 'sections')

    def __init__(self, payload: bytes, serializer_id: int, protocol_id: int,
                 flags: int, sections: Dict[str, bytes]) -> None:
        self.payload = payload
        self.serializer_id = serializer_id
        self.protocol_id = protocol_id
        self.flags = flags
        self.sections = sections
        self.principal = None
        self.signed_as = None
        self.claimed_credentials = sections.get('credentials')

    @property
    def is_authenticated(self) -> bool:
        """Whether a layer proved who sent this.

        Carrying credentials does not make this true: they have not been
        checked by anything here.
        """
        return self.principal is not None

    def credentials(self) -> Optional['Credentials']:
        """Decode the claimed credentials, or ``None`` if there were none.

        Still a claim.  Checking it is the caller's job.
        """
        if self.claimed_credentials is None:
            return None
        return Credentials.decode(self.claimed_credentials)

    def __repr__(self) -> str:
        # Deliberately says nothing about what the credentials contain.
        return ('<Unwrapped %d bytes principal=%r claims_credentials=%s>'
                % (len(self.payload), self.principal,
                   self.claimed_credentials is not None))


class Layer:
    """Something applied to a message's bytes on the way out and undone on
    the way in.

    :py:attr:`flag` is the header bit that records it, so a receiver knows
    to undo it.  A layer may also contribute one section -- an encryption
    nonce, a signature -- by returning it from :py:meth:`apply`.
    """

    #: The header bit this layer sets.
    flag = 0

    #: The section this layer writes, if any: one of the names in
    #: :py:data:`SECTION_ORDER`.
    section = None

    def apply(self, payload: bytes,
              sign_as: Optional[Union[bytes, str]] = None
              ) -> Tuple[bytes, Optional[bytes]]:
        """Transform outgoing bytes.

        :param sign_as: Which identity to sign as, when the caller wants a
            particular one rather than this end's default.  Layers that do
            not sign ignore it.
        :return: ``(payload, section)`` where ``section`` is the bytes to
            carry in this layer's header section, or ``None``.
        """
        raise NotImplementedError

    def remove(self, payload: bytes, sections: Dict[str, bytes],
               result: 'Unwrapped') -> bytes:
        """Undo :py:meth:`apply` on incoming bytes.

        A layer that *proves* who sent the message sets
        ``result.principal``.  It is passed the result rather than keeping
        state of its own because one instance serves every thread.
        """
        raise NotImplementedError


class Framing:
    """Wraps and unwraps messages according to a fixed set of layers.

    :param layers: Applied in order on the way out, reversed on the way in.
    :param require: Flags a received message must carry.  A message without
        them is refused whatever it claims, which is what stops a peer
        opting out of the protection this end requires.
    :param serializer_id: Recorded in the header, so the far end knows how
        the body was serialized.  Meaningful to the protocol, not here.
    :param protocol_id: A second byte the protocol owns, carried and never
        interpreted here.  It exists so a protocol can version the shape of
        its own body without nesting a second envelope inside this one --
        which is the whole reason for one envelope rather than two.
    """

    def __init__(self, layers: Sequence[Layer] = (),
                 require: int = 0,
                 serializer_id: int = 0,
                 protocol_id: int = 0) -> None:
        self.layers = list(layers)
        self.require = require
        self.serializer_id = serializer_id
        self.protocol_id = protocol_id

        # Worked out once, so that wrapping an unsecured message is a
        # branch rather than a walk over an empty pipeline.
        self._flags = 0
        for layer in self.layers:
            self._flags |= layer.flag
        self._plain = not self.layers

        # Credentials are supplied per message rather than by a layer, so
        # requiring them needs no layer to be configured -- a server may
        # insist callers identify themselves without carrying any itself.
        missing = self.require & ~self._flags & ~FLAG_CREDENTIALS
        if missing:
            raise ValueError(
                'this end requires flags 0x%02x but has no layer providing '
                '0x%02x' % (self.require, missing))

    # ------------------------------------------------------------ outgoing --

    def wrap(self, payload: bytes,
             credentials: Optional[bytes] = None,
             serializer_id: Optional[int] = None,
             sign_as: Optional[Union[bytes, str]] = None) -> bytes:
        """Frame a payload for sending.

        :param serializer_id: Overrides the default for this message, so a
            server can answer in the encoding it was addressed in.
        :param sign_as: Overrides which key signs this message, so a server
            can answer under the key the caller used -- one it is known to
            hold, which spares both ends having to agree in advance on which
            of several the reply would carry.
        """
        flags = self._flags
        sections: Dict[str, bytes] = {}

        if credentials is not None:
            flags |= FLAG_CREDENTIALS
            sections['credentials'] = credentials

        if not self._plain:
            for layer in self.layers:
                payload, section = layer.apply(payload, sign_as)
                if section is not None:
                    sections[layer.section] = section

        head = struct.pack(
            HEADER, MAGIC, VERSION, flags,
            self.serializer_id if serializer_id is None else serializer_id,
            self.protocol_id, len(payload))
        if not flags:
            return head + payload

        parts = [head]
        for flag, name in SECTION_ORDER:
            if flags & flag:
                blob = sections.get(name, b'')
                parts.append(struct.pack(_SECTION, len(blob)))
                parts.append(blob)
        parts.append(payload)
        return b''.join(parts)

    # ------------------------------------------------------------ incoming --

    def unwrap(self, data: bytes) -> 'Unwrapped':
        """Unframe a received message.

        :return: an :py:class:`Unwrapped`, which keeps what was *proven*
            about the sender apart from what was merely *claimed*.
        :raises FramingError: if it cannot be read.
        :raises PolicyError: if it does not carry what this end requires.
        """
        if len(data) < HEADER_LEN:
            raise FramingError('message shorter than a header')

        magic, version, flags, serializer_id, protocol_id, length = \
            struct.unpack(HEADER, data[:HEADER_LEN])

        if magic != MAGIC:
            raise FramingError('not a framed message')
        if version != VERSION:
            raise UnsupportedVersion(
                'envelope version %d (this build speaks %d)'
                % (version, VERSION))

        missing = self.require & ~flags
        if missing:
            raise PolicyError(
                'message is missing required protection 0x%02x' % (missing,))

        offset = HEADER_LEN
        sections: Dict[str, bytes] = {}
        for flag, name in SECTION_ORDER:
            if not flags & flag:
                continue
            if len(data) < offset + _SECTION_LEN:
                raise FramingError('truncated section header')
            size, = struct.unpack(_SECTION,
                                  data[offset:offset + _SECTION_LEN])
            offset += _SECTION_LEN
            if len(data) < offset + size:
                raise FramingError('truncated %s section' % (name,))
            sections[name] = data[offset:offset + size]
            offset += size

        payload = data[offset:]
        if len(payload) != length:
            raise FramingError('body length %d does not match header %d'
                               % (len(payload), length))

        result = Unwrapped(payload, serializer_id, protocol_id, flags,
                           sections)

        if flags & ~FLAG_CREDENTIALS:
            for layer in reversed(self.layers):
                if layer.flag and not flags & layer.flag:
                    continue
                payload = layer.remove(payload, sections, result)
            result.payload = payload

        return result

    def __repr__(self) -> str:
        names = ', '.join(type(la).__name__ for la in self.layers) or 'none'
        return '<Framing layers=%s require=0x%02x>' % (names, self.require)
