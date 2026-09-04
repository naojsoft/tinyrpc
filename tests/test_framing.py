#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""The envelope, and the layers that go in it."""

import struct
import time

import pytest

from tinyrpc import framing
from tinyrpc.framing import (FLAG_COMPRESSED, FLAG_CREDENTIALS,
                             FLAG_ENCRYPTED, FLAG_SIGNED, Framing,
                             FramingError, PolicyError, UnsupportedVersion)
from tinyrpc.layers import (Credentials, Deflate, Encrypt, Signature,
                            derive_key)

KEY = b'k' * 32
BODY = b'{"method": "echo"}'


# ------------------------------------------------------------ plain --

def test_an_unsecured_message_is_header_plus_body():
    f = Framing()
    wrapped = f.wrap(BODY)
    assert len(wrapped) == framing.HEADER_LEN + len(BODY)
    assert wrapped.endswith(BODY), "the body should be carried verbatim"

    payload, meta = f.unwrap(wrapped)
    assert payload == BODY
    assert meta['flags'] == 0


def test_the_serializer_is_recorded():
    f = Framing(serializer_id=3)
    _payload, meta = f.unwrap(f.wrap(BODY))
    assert meta['serializer_id'] == 3


def test_an_empty_body_round_trips():
    f = Framing()
    payload, _meta = f.unwrap(f.wrap(b''))
    assert payload == b''


# ------------------------------------------------------------ layers --

def test_compression_round_trips():
    f = Framing(layers=[Deflate()])
    payload = b'x' * 10000
    wrapped = f.wrap(payload)
    assert len(wrapped) < len(payload), "it should actually be smaller"
    assert f.unwrap(wrapped)[0] == payload


def test_a_short_payload_is_not_actually_compressed():
    """Compressing a short message usually makes it longer, so it is stored
    instead -- and must still come back."""
    f = Framing(layers=[Deflate(threshold=1000)])
    assert f.unwrap(f.wrap(b'hi'))[0] == b'hi'


def test_signing_round_trips():
    f = Framing(layers=[Signature(KEY)])
    payload, meta = f.unwrap(f.wrap(BODY))
    assert payload == BODY
    assert meta['flags'] & FLAG_SIGNED


def test_a_tampered_body_is_refused():
    f = Framing(layers=[Signature(KEY)])
    wrapped = bytearray(f.wrap(BODY))
    wrapped[-1] ^= 0xFF
    with pytest.raises(FramingError) as excinfo:
        f.unwrap(bytes(wrapped))
    assert 'signature' in str(excinfo.value)


def test_the_wrong_key_is_refused():
    sender = Framing(layers=[Signature(KEY)])
    receiver = Framing(layers=[Signature(b'j' * 32)])
    with pytest.raises(FramingError):
        receiver.unwrap(sender.wrap(BODY))


def test_a_stale_message_is_refused():
    """Signing covers a timestamp, so a captured message stops working."""
    f = Framing(layers=[Signature(KEY, max_age=0.0001)])
    wrapped = f.wrap(BODY)
    time.sleep(0.01)
    with pytest.raises(FramingError) as excinfo:
        f.unwrap(wrapped)
    assert 'old' in str(excinfo.value)


def test_signing_is_not_deterministic():
    """A nonce goes into every signature, so two identical messages do not
    look identical on the wire."""
    f = Framing(layers=[Signature(KEY)])
    assert f.wrap(BODY) != f.wrap(BODY)


def test_encryption_round_trips():
    f = Framing(layers=[Encrypt(KEY)])
    wrapped = f.wrap(BODY)
    assert BODY not in wrapped, "the plaintext should not be on the wire"
    assert f.unwrap(wrapped)[0] == BODY


def test_encryption_uses_a_fresh_nonce():
    f = Framing(layers=[Encrypt(KEY)])
    assert f.wrap(BODY) != f.wrap(BODY)


def test_a_tampered_ciphertext_is_refused():
    f = Framing(layers=[Encrypt(KEY)])
    wrapped = bytearray(f.wrap(BODY))
    wrapped[-1] ^= 0xFF
    with pytest.raises(FramingError):
        f.unwrap(bytes(wrapped))


def test_a_key_of_the_wrong_size_is_refused():
    with pytest.raises(ValueError) as excinfo:
        Encrypt(b'too short')
    assert 'derive' in str(excinfo.value)


def test_derive_key_gives_a_usable_key():
    key = derive_key('a passphrase')
    assert len(key) == 32
    assert derive_key('a passphrase') == key, "must be deterministic"
    assert derive_key('another') != key


# ------------------------------------------------------- layers together --

def test_compress_then_encrypt_then_sign():
    layers = [Deflate(), Encrypt(KEY), Signature(KEY)]
    f = Framing(layers=layers)
    payload = b'y' * 20000
    wrapped = f.wrap(payload)
    assert f.unwrap(wrapped)[0] == payload
    assert len(wrapped) < len(payload), "compression should still have run"


def test_the_order_is_reversed_on_the_way_in():
    """A receiver built with the same layers in the same order must undo
    them backwards, or nothing round trips."""
    layers = [Deflate(), Signature(KEY)]
    sender = Framing(layers=layers)
    receiver = Framing(layers=[Deflate(), Signature(KEY)])
    assert receiver.unwrap(sender.wrap(BODY))[0] == BODY


# ------------------------------------------------------------- policy --

def test_a_receiver_can_require_a_layer():
    """The point of the exercise: a sender must not be able to opt out of
    the protection this end insists on."""
    unsecured = Framing()
    strict = Framing(layers=[Signature(KEY)], require=FLAG_SIGNED)

    with pytest.raises(PolicyError) as excinfo:
        strict.unwrap(unsecured.wrap(BODY))
    assert 'required protection' in str(excinfo.value)


def test_requiring_encryption_refuses_a_merely_signed_message():
    signed = Framing(layers=[Signature(KEY)])
    strict = Framing(layers=[Encrypt(KEY)], require=FLAG_ENCRYPTED)
    with pytest.raises(PolicyError):
        strict.unwrap(signed.wrap(BODY))


def test_requiring_what_you_cannot_do_is_refused_at_construction():
    """Better to fail here than to refuse every message at run time."""
    with pytest.raises(ValueError) as excinfo:
        Framing(require=FLAG_ENCRYPTED)
    assert 'no layer providing' in str(excinfo.value)


def test_a_receiver_that_requires_nothing_still_accepts_protection():
    lax = Framing(layers=[Signature(KEY)])
    assert lax.unwrap(Framing(layers=[Signature(KEY)]).wrap(BODY))[0] == BODY


# -------------------------------------------------------- credentials --

def test_credentials_are_carried_and_read_back():
    f = Framing()
    creds = Credentials('bob', 'sekrit')
    _payload, meta = f.unwrap(f.wrap(BODY, credentials=creds.encode()))

    assert meta['flags'] & FLAG_CREDENTIALS
    assert Credentials.decode(meta['credentials']) == creds


def test_credentials_survive_the_other_layers():
    f = Framing(layers=[Deflate(), Encrypt(KEY), Signature(KEY)])
    creds = Credentials('bob', 'sekrit')
    payload, meta = f.unwrap(f.wrap(BODY, credentials=creds.encode()))
    assert payload == BODY
    assert Credentials.decode(meta['credentials']).username == 'bob'


def test_credentials_with_awkward_characters():
    creds = Credentials('user:with:colons', 'pass word\nwith stuff')
    assert Credentials.decode(creds.encode()) == creds


def test_a_receiver_can_require_credentials():
    strict = Framing(require=FLAG_CREDENTIALS)
    with pytest.raises(PolicyError):
        strict.unwrap(Framing().wrap(BODY))

    ok = strict.unwrap(Framing().wrap(BODY,
                                      credentials=Credentials('a', 'b').encode()))
    assert ok[0] == BODY


# ------------------------------------------------------ malformed input --

def test_something_that_is_not_a_message():
    with pytest.raises(FramingError):
        Framing().unwrap(b'hello there')


def test_a_truncated_header():
    with pytest.raises(FramingError):
        Framing().unwrap(b'FX')


def test_a_version_from_the_future():
    f = Framing()
    wrapped = bytearray(f.wrap(BODY))
    wrapped[2] = framing.VERSION + 1
    with pytest.raises(UnsupportedVersion):
        f.unwrap(bytes(wrapped))


def test_a_body_that_does_not_match_its_declared_length():
    f = Framing()
    wrapped = bytearray(f.wrap(BODY))
    struct.pack_into('!I', wrapped, framing.HEADER_LEN - 4, 9999)
    with pytest.raises(FramingError) as excinfo:
        f.unwrap(bytes(wrapped))
    assert 'length' in str(excinfo.value)


def test_a_truncated_section():
    f = Framing()
    wrapped = f.wrap(BODY, credentials=b'user\x00pass')
    with pytest.raises(FramingError):
        f.unwrap(wrapped[:framing.HEADER_LEN + 1])
