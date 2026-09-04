#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Layers a :py:class:`~tinyrpc.framing.Framing` can apply.

Each is small and independent, and the order they are given in matters:
compress before encrypt, because ciphertext does not compress, and sign last
so that what is verified is what actually arrived.

Authentication comes in two shapes here, and they answer different
questions:

* :py:class:`Credentials` carries a name and a secret, saying *who* the
  caller claims to be.  It is what HTTP Basic authentication does, and what
  Gen2's ``authDict`` expects -- but it sends a reusable secret, so it is
  only as private as the connection.
* :py:class:`Signature` proves the sender holds a particular key, without
  sending it, and detects any change to the message on the way.  Keys have
  names, so with a key per service a verified message says which service
  sent it; with one key shared by everything it says only that the sender is
  somewhere inside the trusted set.

Neither hides the message.  Only encryption does that.
"""

import hashlib
import hmac
import os
import struct
import time
import zlib
from typing import Any, Dict, Mapping, Optional, Tuple, Union

from .framing import (FLAG_COMPRESSED, FLAG_ENCRYPTED, FLAG_SIGNED,
                      FramingError, Layer, Unwrapped)


def _as_bytes(value: Union[bytes, str]) -> bytes:
    """UTF-8 encode a name or key, or pass bytes through."""
    return value if isinstance(value, bytes) else value.encode('utf-8')


class Deflate(Layer):
    """Compress with :py:mod:`zlib`.

    :param level: 1 is fast and slack, 9 is slow and tight; 6 is zlib's own
        default.
    :param threshold: Payloads smaller than this are passed through, since
        compressing a short message usually makes it longer.  Note the flag
        is still set, so the far end still calls :py:meth:`remove` -- zlib
        round-trips a stored block fine, and a per-message decision would
        otherwise need its own header bit.
    """

    flag = FLAG_COMPRESSED

    def __init__(self, level: int = 6, threshold: int = 256) -> None:
        self.level = level
        self.threshold = threshold

    def apply(self, payload: bytes) -> Tuple[bytes, Optional[bytes]]:
        if len(payload) < self.threshold:
            return zlib.compress(payload, 0), None
        return zlib.compress(payload, self.level), None

    def remove(self, payload: bytes, sections: Dict[str, bytes],
               result: Unwrapped) -> bytes:
        try:
            return zlib.decompress(payload)
        except zlib.error as e:
            raise FramingError('could not decompress: %s' % (e,)) from None


class Signature(Layer):
    """Sign with HMAC, so tampering and forgery are both detectable.

    Each key has a name, and the name travels with the message so the far
    end knows which key to check it against.  Naming keys is what makes
    identity per-service: with one secret shared by everything, a valid
    signature proves only that the sender is somewhere inside the trusted
    set, and any member of that set can sign as any other.  With a key per
    service, a verified message names exactly one holder.

    The name is not trusted -- it only selects a key.  A sender claiming to
    be ``taskmgr`` without holding taskmgr's key produces a signature that
    does not verify, and the name is itself covered by the MAC, so it cannot
    be swapped onto an otherwise valid message.

    The signature covers a timestamp and a nonce as well, so a captured
    message stops working once ``max_age`` has passed, and optionally an
    *audience*: the name of the service the connection serves.  The audience
    is never sent -- each end mixes in the value it was configured with --
    so a message captured on the way to one service cannot be replayed at
    another, even by a peer that legitimately talks to both.

    A key with no name proves possession without naming anyone, so it leaves
    :py:attr:`~tinyrpc.framing.Unwrapped.principal` unset.  A receiver that
    wants to insist merely that messages *are* signed should say so with
    ``require=FLAG_SIGNED`` on the :py:class:`~tinyrpc.framing.Framing`;
    that is a different question from who sent them, and has its own answer.

    :param keys: What this end will accept, as ``{key_id: key}`` or
        ``{key_id: (key, principal)}``.  The principal defaults to the key
        id, since the id names whoever holds it.  A bare key may be given
        instead, for the simple case of one shared, unnamed secret.
    :param sign_as: Which key id to sign outgoing messages with.  Optional
        when there is only one key; required when there is a choice, since
        guessing would quietly pick an identity.
    :param digest: Anything :py:mod:`hashlib` names.
    :param max_age: Seconds a message stays acceptable, or ``None`` to not
        check.  Rejecting old messages is what makes replay expensive; it
        needs the two clocks within roughly this much of each other.
    :param audience: The name of the service this connection serves.  Both
        ends must agree, including on ``None``.
    """

    flag = FLAG_SIGNED
    section = 'signature'

    #: ``timestamp, nonce, key id length, audience length``.  Both lengths
    #: are covered by the MAC, so the fields after the stamp cannot be
    #: re-divided into a different but equally valid reading.
    _STAMP = '!d8sBB'
    _STAMP_LEN = struct.calcsize(_STAMP)

    def __init__(self,
                 keys: Union[bytes, str, Mapping[str, Any]],
                 sign_as: Optional[str] = None,
                 digest: str = 'sha256',
                 max_age: Optional[float] = 300.0,
                 audience: Optional[str] = None) -> None:
        if isinstance(keys, (bytes, str)):
            keys = {'': keys}
        if not keys:
            raise ValueError('at least one signing key is required')

        self.digest = digest
        self.max_age = max_age

        self._keys: Dict[bytes, bytes] = {}
        self._principals: Dict[bytes, Optional[str]] = {}
        for key_id, entry in keys.items():
            key, principal = (entry if isinstance(entry, tuple)
                              else (entry, key_id))
            if not key:
                raise ValueError('the key named %r is empty' % (key_id,))
            ident = _as_bytes(key_id)
            if len(ident) > 255:
                raise ValueError('key id %r is too long to carry' % (key_id,))
            self._keys[ident] = _as_bytes(key)
            # An empty name is no name, not a principal called "".
            self._principals[ident] = principal or None

        if sign_as is None:
            if len(self._keys) > 1:
                raise ValueError('several keys are configured; say which one '
                                 'to sign as')
            self._sign_as = next(iter(self._keys))
        else:
            self._sign_as = _as_bytes(sign_as)
            if self._sign_as not in self._keys:
                raise ValueError('there is no key named %r to sign with'
                                 % (sign_as,))
        self._sign_key = self._keys[self._sign_as]

        self._audience = _as_bytes(audience) if audience else b''
        if len(self._audience) > 255:
            raise ValueError('audience name is too long to bind to')

    def _mac(self, key: bytes, stamp: bytes, key_id: bytes,
             payload: bytes) -> bytes:
        mac = hmac.new(key, digestmod=self.digest)
        mac.update(stamp)
        mac.update(key_id)
        mac.update(self._audience)
        mac.update(payload)
        return mac.digest()

    def apply(self, payload: bytes) -> Tuple[bytes, Optional[bytes]]:
        stamp = struct.pack(self._STAMP, time.time(), os.urandom(8),
                            len(self._sign_as), len(self._audience))
        mac = self._mac(self._sign_key, stamp, self._sign_as, payload)
        return payload, stamp + self._sign_as + mac

    def remove(self, payload: bytes, sections: Dict[str, bytes],
               result: Unwrapped) -> bytes:
        blob = sections.get('signature')
        if not blob or len(blob) <= self._STAMP_LEN:
            raise FramingError('message is not signed')

        stamp = blob[:self._STAMP_LEN]
        sent, _nonce, id_len, aud_len = struct.unpack(self._STAMP, stamp)

        rest = blob[self._STAMP_LEN:]
        if len(rest) <= id_len:
            raise FramingError('truncated signature')
        key_id, mac = rest[:id_len], rest[id_len:]

        # Looked at before the MAC only because a mismatch here is almost
        # always a misconfiguration, and saying so beats "signature does not
        # match".  Neither the audience nor any key travels, so this tells a
        # forger nothing it could not already guess.
        if aud_len != len(self._audience):
            raise FramingError('message was not signed for this service')

        key = self._keys.get(key_id)
        if key is None:
            raise FramingError('no key named %r is accepted here'
                               % (key_id.decode('utf-8', 'replace'),))

        if not hmac.compare_digest(mac,
                                   self._mac(key, stamp, key_id, payload)):
            raise FramingError('signature does not match')

        if self.max_age is not None:
            age = abs(time.time() - sent)
            if age > self.max_age:
                raise FramingError(
                    'message is %.0fs old, older than the %.0fs allowed'
                    % (age, self.max_age))

        # Only now, with the key identified, the MAC matching and the
        # message fresh, is there anything proven to report.
        result.principal = self._principals[key_id]
        return payload


class Encrypt(Layer):
    """Encrypt with NaCl's secret box, which also authenticates.

    Requires :py:mod:`nacl`.  A fresh nonce is generated for each message and
    carried in its own section; reusing one with the same key would leak the
    plaintext, so it is never derived from anything predictable.

    Note this authenticates the *message*, not the sender: anyone holding the
    key can produce a valid box.  With one key per pair of peers that is a
    useful statement; with one key shared by everyone it is not.

    It therefore reports no principal, even though the box is authenticated.
    Confidentiality and identity are separate questions, and keeping the
    answer to the second in one place -- :py:class:`Signature` -- means there
    is never a doubt about which layer decided who the caller is.
    """

    flag = FLAG_ENCRYPTED
    section = 'nonce'

    def __init__(self, key: bytes) -> None:
        try:
            from nacl.secret import SecretBox
        except ImportError:  # pragma: no cover - depends on the environment
            raise ImportError(
                'encryption needs PyNaCl: pip install pynacl') from None

        if len(key) != SecretBox.KEY_SIZE:
            raise ValueError('key must be exactly %d bytes; derive one from '
                             'a passphrase rather than padding it'
                             % SecretBox.KEY_SIZE)
        self._box = SecretBox(key)
        self._nonce_size = SecretBox.NONCE_SIZE

    def apply(self, payload: bytes) -> Tuple[bytes, Optional[bytes]]:
        nonce = os.urandom(self._nonce_size)
        return self._box.encrypt(payload, nonce).ciphertext, nonce

    def remove(self, payload: bytes, sections: Dict[str, bytes],
               result: Unwrapped) -> bytes:
        nonce = sections.get('nonce')
        if not nonce:
            raise FramingError('encrypted message carries no nonce')
        try:
            return self._box.decrypt(payload, nonce)
        except Exception as e:
            raise FramingError('could not decrypt: %s' % (e,)) from None


def derive_key(passphrase: str, salt: bytes = b'tinyrpc-flexrpc',
               length: int = 32) -> bytes:
    """Turn a passphrase into a key of the right length.

    Uses PBKDF2, so a weak passphrase is at least expensive to attack.  A key
    generated with :py:func:`os.urandom` is better where one can be
    distributed; this is for where a passphrase is what there is.
    """
    return hashlib.pbkdf2_hmac('sha256', passphrase.encode('utf-8'),
                               salt, 200000, dklen=length)


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
