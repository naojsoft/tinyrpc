#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Layers a :py:class:`~tinyrpc.framing.Framing` can apply.

Each is small and independent, and the order they are given in matters:
compress before encrypt, because ciphertext does not compress, and sign last
so that what is verified is what actually arrived.

Authentication comes in two shapes here, and they answer different
questions:

* :py:class:`~tinyrpc.framing.Credentials` carries a name and a secret,
  saying *who* the caller claims to be.  It is what HTTP Basic
  authentication does -- but it sends a reusable secret, so it is only as
  private as the connection.  It lives with the envelope rather than here,
  because it transforms nothing and so is not a layer at all.
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
import threading
import time
import zlib
from typing import Any, Dict, Mapping, Optional, Tuple, Union

from .framing import (FLAG_COMPRESSED, FLAG_ENCRYPTED, FLAG_SIGNED,
                      Credentials, FramingError, Layer, Unwrapped)

# Credentials lives with the envelope rather than here: it transforms
# nothing, so it is not a Layer, and the header section it travels in is
# defined there.  Re-exported because this is where it used to be.
__all__ = ['Credentials', 'Deflate', 'Ed25519Signature', 'Encrypt',
           'Signature', 'derive_key', 'generate_signing_key']


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

    def apply(self, payload: bytes,
              sign_as: Optional[Union[bytes, str]] = None
              ) -> Tuple[bytes, Optional[bytes]]:
        if len(payload) < self.threshold:
            return zlib.compress(payload, 0), None
        return zlib.compress(payload, self.level), None

    def remove(self, payload: bytes, sections: Dict[str, bytes],
               result: Unwrapped) -> bytes:
        try:
            return zlib.decompress(payload)
        except zlib.error as e:
            raise FramingError('could not decompress: %s' % (e,)) from None


class _ReplayCache:
    """Remembers nonces for long enough that ``max_age`` means something.

    Without it, a captured message can be sent again and again until it
    ages out; the timestamp bounds that window but does not close it.

    Two generations rather than an expiry per entry: when the older one ages
    out it is dropped whole, which costs an assignment instead of a scan.
    ``capacity`` bounds the memory, and reaching it drops the older
    generation early -- shortening the window rather than either refusing
    honest traffic or growing without limit.  :py:attr:`overflows` counts
    that, since it means the window is no longer the one configured.
    """

    __slots__ = ('window', 'capacity', 'overflows', '_new', '_old',
                 '_rolled', '_lock')

    def __init__(self, window: float, capacity: int) -> None:
        self.window = window
        self.capacity = capacity
        self.overflows = 0
        self._new: Dict[bytes, None] = {}
        self._old: Dict[bytes, None] = {}
        self._rolled = time.monotonic()
        self._lock = threading.Lock()

    def seen(self, token: bytes) -> bool:
        """Record a nonce, and say whether it had already been recorded."""
        now = time.monotonic()
        with self._lock:
            if now - self._rolled >= self.window:
                # Two windows of silence and both generations are stale.
                self._old = ({} if now - self._rolled >= 2 * self.window
                             else self._new)
                self._new = {}
                self._rolled = now

            if token in self._new or token in self._old:
                return True

            if len(self._new) + len(self._old) >= self.capacity:
                self.overflows += 1
                self._old = {}
                if len(self._new) >= self.capacity:
                    self._new = {}

            self._new[token] = None
            return False


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
    :param replay_cache: How many recent nonces to remember, or 0 to
        remember none.  Off by default: without it a captured message can be
        replayed until ``max_age`` passes, and with it that window closes,
        at the cost of a set the size of the traffic crossing it.  See
        :py:class:`_ReplayCache` for what happens when it fills.
    """

    flag = FLAG_SIGNED
    section = 'signature'

    #: ``timestamp, nonce, key id length, audience length``.  Both lengths
    #: are covered by the MAC, so the fields after the stamp cannot be
    #: re-divided into a different but equally valid reading.
    _STAMP = '!d8sBB'
    _STAMP_LEN = struct.calcsize(_STAMP)

    #: Whether this end must end up able to sign.  A verifier holding
    #: several public keys and no private one has no identity to pick, so
    #: :py:class:`Ed25519Signature` clears this; a shared secret can always
    #: sign with any key it holds, so ambiguity there is an error.
    _needs_a_signing_identity = True

    def __init__(self,
                 keys: Union[bytes, str, Mapping[str, Any]],
                 sign_as: Optional[Union[bytes, str]] = None,
                 digest: str = 'sha256',
                 max_age: Optional[float] = 300.0,
                 audience: Optional[str] = None,
                 replay_cache: int = 0) -> None:
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
            self._keys[ident] = self._load(key)
            # An empty name is no name, not a principal called "".
            self._principals[ident] = principal or None

        if sign_as is not None:
            self._sign_as = _as_bytes(sign_as)
            if self._sign_as not in self._keys:
                raise ValueError('there is no key named %r to sign with'
                                 % (sign_as,))
        elif len(self._keys) == 1:
            self._sign_as = next(iter(self._keys))
        elif self._needs_a_signing_identity:
            raise ValueError('several keys are configured; say which one '
                             'to sign as')
        else:
            self._sign_as = b''
        self._sign_key = self._keys.get(self._sign_as)

        self._audience = _as_bytes(audience) if audience else b''
        if len(self._audience) > 255:
            raise ValueError('audience name is too long to bind to')

        self._replay: Optional[_ReplayCache] = None
        if replay_cache:
            if max_age is None:
                raise ValueError('a replay cache needs a max_age to bound '
                                 'what it has to remember')
            # Twice max_age, because a clock a little ahead is accepted and
            # its messages must stay remembered for as long.
            self._replay = _ReplayCache(2 * max_age, replay_cache)

    # --- what a subclass changes to sign differently -------------------

    def _load(self, key: Any) -> Any:
        """Turn a configured key into whatever signing needs."""
        return _as_bytes(key)

    def _make(self, key: Any, stamp: bytes, key_id: bytes,
              payload: bytes) -> bytes:
        mac = hmac.new(key, digestmod=self.digest)
        mac.update(stamp)
        mac.update(key_id)
        mac.update(self._audience)
        mac.update(payload)
        return mac.digest()

    def _check(self, key: Any, stamp: bytes, key_id: bytes, payload: bytes,
               signature: bytes) -> bool:
        return hmac.compare_digest(signature,
                                   self._make(key, stamp, key_id, payload))

    # -------------------------------------------------------------------

    def apply(self, payload: bytes,
              sign_as: Optional[Union[bytes, str]] = None
              ) -> Tuple[bytes, Optional[bytes]]:
        if sign_as is None:
            key_id, key = self._sign_as, self._sign_key
        else:
            key_id = _as_bytes(sign_as)
            key = self._keys.get(key_id)
            if key is None:
                raise FramingError('asked to sign as %r, which this end has '
                                   'no key for'
                                   % (key_id.decode('utf-8', 'replace'),))
        if key is None:
            raise FramingError('this end holds no signing key; it can only '
                               'verify')

        stamp = struct.pack(self._STAMP, time.time(), os.urandom(8),
                            len(key_id), len(self._audience))
        mac = self._make(key, stamp, key_id, payload)
        return payload, stamp + key_id + mac

    def remove(self, payload: bytes, sections: Dict[str, bytes],
               result: Unwrapped) -> bytes:
        blob = sections.get('signature')
        if not blob or len(blob) <= self._STAMP_LEN:
            raise FramingError('message is not signed')

        stamp = blob[:self._STAMP_LEN]
        sent, nonce, id_len, aud_len = struct.unpack(self._STAMP, stamp)

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

        if not self._check(key, stamp, key_id, payload, mac):
            raise FramingError('signature does not match')

        if self.max_age is not None:
            age = abs(time.time() - sent)
            if age > self.max_age:
                raise FramingError(
                    'message is %.0fs old, older than the %.0fs allowed'
                    % (age, self.max_age))

        # After verifying, so unauthenticated traffic cannot fill the cache,
        # and after the age check, so nothing is remembered that would have
        # been refused anyway.  The key id is part of the token: two senders
        # drawing the same 8 bytes is unlikely but need not be an incident.
        if self._replay is not None and self._replay.seen(key_id + nonce):
            raise FramingError('this message has already been delivered')

        # Only now, with the key identified, the MAC matching and the
        # message fresh, is there anything proven to report.
        result.principal = self._principals[key_id]
        result.signed_as = key_id.decode('utf-8', 'replace')
        return payload


class Ed25519Signature(Signature):
    """Sign with Ed25519, so verifying does not require the power to forge.

    HMAC's key is symmetric: whoever can check a signature can also produce
    one.  On a trusted network that is fine -- but it means every service
    holding the key to verify ``status`` can also *be* ``status``, and a
    single compromised host forges for everyone.  Here each service keeps a
    private key nobody else has, and publishes a public key that only
    checks.  A stolen name service, holding nothing but public keys, cannot
    impersonate anything it lists.

    The wire format, key ids, freshness and audience binding are all
    :py:class:`Signature`'s; only what goes in the signature section
    changes, from a 32-byte MAC to a 64-byte signature.

    Requires :py:mod:`nacl`.

    :param keys: The public keys this end accepts, as ``{key_id: public}``
        or ``{key_id: (public, principal)}``, each 32 bytes.
    :param sign_as: Which id this end signs as.  Needed only when it signs.
    :param signing_key: This end's own 32-byte private key, or an already
        built :py:class:`nacl.signing.SigningKey`, or ``None`` for an end
        that only verifies -- a monitor, or a name service that should not
        be able to speak for what it registers.
    :param max_age: As :py:class:`Signature`.
    :param audience: As :py:class:`Signature`.
    :param replay_cache: As :py:class:`Signature`.
    """

    def __init__(self,
                 keys: Mapping[str, Any],
                 sign_as: Optional[Union[bytes, str]] = None,
                 signing_key: Optional[Any] = None,
                 max_age: Optional[float] = 300.0,
                 audience: Optional[str] = None,
                 replay_cache: int = 0) -> None:
        try:
            from nacl.exceptions import BadSignatureError
            from nacl.signing import SigningKey, VerifyKey
        except ImportError:  # pragma: no cover - depends on the environment
            raise ImportError(
                'Ed25519 signing needs PyNaCl: pip install pynacl') from None

        self._VerifyKey = VerifyKey
        self._BadSignature = BadSignatureError

        own = None
        if signing_key is not None:
            own = (signing_key if isinstance(signing_key, SigningKey)
                   else SigningKey(_as_bytes(signing_key)))

        # An end with no private key has no identity to pick, however many
        # public ones it holds, so it must not be made to choose.
        self._needs_a_signing_identity = own is not None

        super().__init__(keys, sign_as=sign_as, max_age=max_age,
                         audience=audience, replay_cache=replay_cache)

        self._sign_key = own
        if own is not None:
            # Catch the mismatch here rather than as unexplained verification
            # failures on every message this end ever sends.
            published = self._keys[self._sign_as]
            if bytes(own.verify_key) != bytes(published):
                raise ValueError(
                    'the signing key given does not match the public key '
                    'registered for %r' % (self._sign_as.decode(),))

    def _load(self, key: Any) -> Any:
        if isinstance(key, self._VerifyKey):
            return key
        return self._VerifyKey(_as_bytes(key))

    def _make(self, key: Any, stamp: bytes, key_id: bytes,
              payload: bytes) -> bytes:
        return key.sign(b''.join((stamp, key_id, self._audience,
                                  payload))).signature

    def _check(self, key: Any, stamp: bytes, key_id: bytes, payload: bytes,
               signature: bytes) -> bool:
        try:
            key.verify(b''.join((stamp, key_id, self._audience, payload)),
                       signature)
        except self._BadSignature:
            return False
        return True


def generate_signing_key() -> Tuple[bytes, bytes]:
    """Make an Ed25519 key pair, as ``(private, public)`` raw bytes.

    The private half stays on the service it belongs to; the public half is
    what everyone else is configured with.
    """
    try:
        from nacl.signing import SigningKey
    except ImportError:  # pragma: no cover - depends on the environment
        raise ImportError(
            'Ed25519 signing needs PyNaCl: pip install pynacl') from None
    key = SigningKey.generate()
    return bytes(key), bytes(key.verify_key)


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

    def apply(self, payload: bytes,
              sign_as: Optional[Union[bytes, str]] = None
              ) -> Tuple[bytes, Optional[bytes]]:
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
