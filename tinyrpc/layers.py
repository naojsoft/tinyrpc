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
* :py:class:`Signature` proves the sender holds a shared key, without
  sending it, and detects any change to the message on the way.  It answers
  "may this caller act" rather than "who is it", which for one service
  talking to another is usually the question.

Neither hides the message.  Only encryption does that.
"""

import hashlib
import hmac
import os
import struct
import time
import zlib
from typing import Any, Dict, Optional, Tuple

from .framing import (FLAG_COMPRESSED, FLAG_ENCRYPTED, FLAG_SIGNED,
                      FramingError, Layer)


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
               result: Any) -> bytes:
        try:
            return zlib.decompress(payload)
        except zlib.error as e:
            raise FramingError('could not decompress: %s' % (e,)) from None


class Signature(Layer):
    """Sign with HMAC, so tampering and forgery are both detectable.

    The signature covers a timestamp and a nonce as well as the payload, so
    a captured message cannot be replayed once ``max_age`` has passed --
    provided the receiver's clock is roughly right.

    :param key: The shared secret.  Both ends need the same one.
    :param digest: Anything :py:mod:`hashlib` names.
    :param max_age: Seconds a message stays acceptable, or ``None`` to not
        check.  Rejecting old messages is what makes replay expensive; it
        needs the two clocks within roughly this much of each other.
    :param principal: What a verified message proves the sender to be.  With
        one shared key that is only as specific as the key is: everyone
        holding it can sign as this principal, so name the key's realm --
        "gen2-internal" -- rather than any one service.  Per-service
        identity needs a key per service, and the key's name covered by the
        signature so it cannot be swapped.
    """

    flag = FLAG_SIGNED
    section = 'signature'

    _STAMP = '!d8s'
    _STAMP_LEN = struct.calcsize(_STAMP)

    def __init__(self, key: bytes, digest: str = 'sha256',
                 max_age: Optional[float] = 300.0,
                 principal: Optional[str] = None) -> None:
        if not key:
            raise ValueError('a signing key is required')
        self.key = key if isinstance(key, bytes) else key.encode('utf-8')
        self.digest = digest
        self.max_age = max_age
        self.principal = principal

    def _mac(self, stamp: bytes, payload: bytes) -> bytes:
        return hmac.new(self.key, stamp + payload, self.digest).digest()

    def apply(self, payload: bytes) -> Tuple[bytes, Optional[bytes]]:
        stamp = struct.pack(self._STAMP, time.time(), os.urandom(8))
        return payload, stamp + self._mac(stamp, payload)

    def remove(self, payload: bytes, sections: Dict[str, bytes],
               result: Any) -> bytes:
        blob = sections.get('signature')
        if not blob or len(blob) <= self._STAMP_LEN:
            raise FramingError('message is not signed')

        stamp, mac = blob[:self._STAMP_LEN], blob[self._STAMP_LEN:]
        if not hmac.compare_digest(mac, self._mac(stamp, payload)):
            raise FramingError('signature does not match')

        if self.max_age is not None:
            sent, _nonce = struct.unpack(self._STAMP, stamp)
            age = abs(time.time() - sent)
            if age > self.max_age:
                raise FramingError(
                    'message is %.0fs old, older than the %.0fs allowed'
                    % (age, self.max_age))

        # Only now, with the signature checked and the message fresh, is
        # there anything proven to report.
        if self.principal is not None:
            result.principal = self.principal
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
               result: Any) -> bytes:
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
