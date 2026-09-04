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

    got = f.unwrap(wrapped)
    assert got.payload == BODY
    assert got.flags == 0


def test_the_serializer_is_recorded():
    f = Framing(serializer_id=3)
    assert f.unwrap(f.wrap(BODY)).serializer_id == 3


def test_an_empty_body_round_trips():
    f = Framing()
    assert f.unwrap(f.wrap(b'')).payload == b''


# ------------------------------------------------------------ layers --

def test_compression_round_trips():
    f = Framing(layers=[Deflate()])
    payload = b'x' * 10000
    wrapped = f.wrap(payload)
    assert len(wrapped) < len(payload), "it should actually be smaller"
    assert f.unwrap(wrapped).payload == payload


def test_a_short_payload_is_not_actually_compressed():
    """Compressing a short message usually makes it longer, so it is stored
    instead -- and must still come back."""
    f = Framing(layers=[Deflate(threshold=1000)])
    assert f.unwrap(f.wrap(b'hi')).payload == b'hi'


def test_signing_round_trips():
    f = Framing(layers=[Signature(KEY)])
    got = f.unwrap(f.wrap(BODY))
    assert got.payload == BODY
    assert got.flags & FLAG_SIGNED


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
    assert f.unwrap(wrapped).payload == BODY


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
    assert f.unwrap(wrapped).payload == payload
    assert len(wrapped) < len(payload), "compression should still have run"


def test_the_order_is_reversed_on_the_way_in():
    """A receiver built with the same layers in the same order must undo
    them backwards, or nothing round trips."""
    layers = [Deflate(), Signature(KEY)]
    sender = Framing(layers=layers)
    receiver = Framing(layers=[Deflate(), Signature(KEY)])
    assert receiver.unwrap(sender.wrap(BODY)).payload == BODY


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
    assert lax.unwrap(Framing(layers=[Signature(KEY)]).wrap(BODY)).payload == BODY


# -------------------------------------------------------- credentials --

def test_credentials_are_carried_and_read_back():
    f = Framing()
    creds = Credentials('bob', 'sekrit')
    got = f.unwrap(f.wrap(BODY, credentials=creds.encode()))

    assert got.flags & FLAG_CREDENTIALS
    assert got.credentials() == creds


def test_credentials_survive_the_other_layers():
    f = Framing(layers=[Deflate(), Encrypt(KEY), Signature(KEY)])
    creds = Credentials('bob', 'sekrit')
    got = f.unwrap(f.wrap(BODY, credentials=creds.encode()))
    assert got.payload == BODY
    assert got.credentials().username == 'bob'


def test_credentials_with_awkward_characters():
    creds = Credentials('user:with:colons', 'pass word\nwith stuff')
    assert Credentials.decode(creds.encode()) == creds


def test_a_receiver_can_require_credentials():
    strict = Framing(require=FLAG_CREDENTIALS)
    with pytest.raises(PolicyError):
        strict.unwrap(Framing().wrap(BODY))

    ok = strict.unwrap(Framing().wrap(BODY,
                                      credentials=Credentials('a', 'b').encode()))
    assert ok.payload == BODY


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


# ------------------------------------------- proven apart from claimed --

def test_credentials_alone_prove_nothing():
    """The distinction the split exists for: a sender saying who it is does
    not make it so."""
    f = Framing()
    got = f.unwrap(f.wrap(BODY, credentials=Credentials('bob', 'x').encode()))

    assert got.claimed_credentials is not None, "the claim is carried"
    assert got.principal is None, "but nothing has checked it"
    assert not got.is_authenticated


def test_a_verified_signature_names_a_principal():
    f = Framing(layers=[Signature(KEY, principal='gen2-internal')])
    got = f.unwrap(f.wrap(BODY))

    assert got.principal == 'gen2-internal'
    assert got.is_authenticated
    assert got.claimed_credentials is None


def test_a_forged_message_never_yields_a_principal():
    """A failed signature raises, so no caller ever sees a principal from a
    message that did not verify."""
    sender = Framing(layers=[Signature(b'wrong key' + b'-' * 23)])
    receiver = Framing(layers=[Signature(KEY, principal='gen2-internal')])
    with pytest.raises(FramingError):
        receiver.unwrap(sender.wrap(BODY))


def test_a_sender_cannot_assert_a_principal_through_credentials():
    """Credentials are sender-controlled; principal is not.  Putting a name
    in the credentials must not make it a proven identity."""
    f = Framing()
    got = f.unwrap(f.wrap(BODY,
                          credentials=Credentials('root', 'hunter2').encode()))
    assert got.principal is None
    assert not got.is_authenticated


def test_signing_without_a_principal_still_verifies():
    """A shared key with no name attached still proves possession; it just
    has no identity to report."""
    f = Framing(layers=[Signature(KEY)])
    got = f.unwrap(f.wrap(BODY))
    assert got.payload == BODY
    assert got.principal is None


def test_encryption_reports_no_principal():
    """The box is authenticated, but with a shared key that says nothing
    about which holder sent it -- so identity stays with Signature."""
    f = Framing(layers=[Encrypt(KEY)])
    got = f.unwrap(f.wrap(BODY))
    assert got.payload == BODY
    assert got.principal is None


def test_signed_and_credentialed_together():
    """Both may be present, and they still mean different things."""
    f = Framing(layers=[Signature(KEY, principal='gen2-internal')])
    got = f.unwrap(f.wrap(BODY,
                          credentials=Credentials('bob', 'x').encode()))
    assert got.principal == 'gen2-internal'
    assert got.credentials().username == 'bob'


def test_the_repr_does_not_leak_the_secret():
    f = Framing()
    got = f.unwrap(f.wrap(BODY,
                          credentials=Credentials('bob', 'hunter2').encode()))
    assert 'hunter2' not in repr(got)
    assert 'bob' not in repr(got)
