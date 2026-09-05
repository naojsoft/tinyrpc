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
from tinyrpc.layers import (Credentials, Deflate, Ed25519Signature,
                            Encrypt, Signature, derive_key,
                            generate_signing_key)

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
    f = Framing(layers=[Signature({'gen2-internal': KEY})])
    got = f.unwrap(f.wrap(BODY))

    assert got.principal == 'gen2-internal'
    assert got.is_authenticated
    assert got.claimed_credentials is None


def test_a_forged_message_never_yields_a_principal():
    """A failed signature raises, so no caller ever sees a principal from a
    message that did not verify."""
    sender = Framing(layers=[Signature(b'wrong key' + b'-' * 23)])
    receiver = Framing(layers=[Signature({'gen2-internal': KEY})])
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
    """An unnamed key still proves possession; it just has no identity to
    report.  Insisting a message be signed at all is the Framing's job."""
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
    f = Framing(layers=[Signature({'gen2-internal': KEY})])
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


# ---------------------------------------------------- per-service keys --

KEY_A = b'a' * 32
KEY_B = b'b' * 32

#: Where a key id sits in a signed-only message: header, the section's own
#: 2-byte length, then the stamp.
_ID_AT = framing.HEADER_LEN + 2 + Signature._STAMP_LEN


def receiver(**kw):
    """One end holding both services' keys, as a name service would."""
    return Framing(layers=[Signature({'status': KEY_A, 'taskmgr': KEY_B},
                                     sign_as='status', **kw)])


def sender(name, key, **kw):
    return Framing(layers=[Signature({name: key}, **kw)])


def test_a_verified_message_names_which_service_sent_it():
    """The point of per-service keys: not "someone we trust" but "status"."""
    end = receiver()
    assert end.unwrap(sender('status', KEY_A).wrap(BODY)).principal == 'status'
    assert end.unwrap(sender('taskmgr', KEY_B).wrap(BODY)).principal == 'taskmgr'


def test_one_service_cannot_sign_as_another():
    """Holding status's key must not let it speak as taskmgr.  The id is a
    claim; the key is the proof, and they have to agree."""
    liar = sender('taskmgr', KEY_A)          # taskmgr's name, status's key
    with pytest.raises(FramingError) as excinfo:
        receiver().unwrap(liar.wrap(BODY))
    assert 'does not match' in str(excinfo.value)


def test_relabelling_a_genuine_message_cannot_promote_it():
    """The id is covered by the MAC, so it cannot be edited on the wire.

    Two names on one key isolate that: nothing but the MAC's coverage of the
    id distinguishes them, and getting it wrong would let anyone holding the
    key pick which principal they arrive as.
    """
    end = Framing(layers=[Signature({'aaa': (KEY_A, 'lowly'),
                                     'bbb': (KEY_A, 'admin')},
                                    sign_as='aaa')])
    assert end.unwrap(end.wrap(BODY)).principal == 'lowly'

    wrapped = bytearray(end.wrap(BODY))
    assert bytes(wrapped[_ID_AT:_ID_AT + 3]) == b'aaa', "found the id"
    wrapped[_ID_AT:_ID_AT + 3] = b'bbb'

    with pytest.raises(FramingError) as excinfo:
        end.unwrap(bytes(wrapped))
    assert 'does not match' in str(excinfo.value)


def test_a_key_this_end_does_not_know_is_refused():
    with pytest.raises(FramingError) as excinfo:
        receiver().unwrap(sender('stranger', KEY_A).wrap(BODY))
    assert 'stranger' in str(excinfo.value)


def test_the_principal_defaults_to_the_key_id():
    f = Framing(layers=[Signature({'status': KEY_A})])
    assert f.unwrap(f.wrap(BODY)).principal == 'status'


def test_a_key_can_speak_for_a_different_principal():
    """The id names the key; who that key acts as can be said separately."""
    f = Framing(layers=[Signature({'status-2024': (KEY_A, 'status')})])
    assert f.unwrap(f.wrap(BODY)).principal == 'status'


def test_an_unnamed_key_names_nobody():
    f = Framing(layers=[Signature(KEY_A)])
    got = f.unwrap(f.wrap(BODY))
    assert got.payload == BODY
    assert got.principal is None


def test_a_choice_of_keys_needs_an_explicit_one_to_sign_with():
    """Guessing would quietly pick an identity, so it is refused here rather
    than silently got wrong on every message."""
    with pytest.raises(ValueError) as excinfo:
        Signature({'status': KEY_A, 'taskmgr': KEY_B})
    assert 'which one' in str(excinfo.value)


def test_signing_as_a_key_that_is_not_there():
    with pytest.raises(ValueError) as excinfo:
        Signature({'status': KEY_A}, sign_as='taskmgr')
    assert 'taskmgr' in str(excinfo.value)


def test_an_empty_key_is_refused():
    with pytest.raises(ValueError):
        Signature({'status': b''})


def test_no_keys_at_all_is_refused():
    with pytest.raises(ValueError):
        Signature({})


def test_a_key_id_too_long_to_carry():
    with pytest.raises(ValueError) as excinfo:
        Signature({'x' * 256: KEY_A})
    assert 'too long' in str(excinfo.value)


def test_key_ids_survive_the_other_layers():
    layers = [Deflate(), Encrypt(KEY), Signature({'status': KEY_A})]
    f = Framing(layers=layers)
    got = f.unwrap(f.wrap(b'z' * 5000))
    assert got.payload == b'z' * 5000
    assert got.principal == 'status'


# --------------------------------------------------------- audience --

def test_a_message_for_one_service_is_refused_by_another():
    """Binding the signature to the callee means a peer that legitimately
    talks to both cannot have its request replayed at the wrong one."""
    to_status = sender('gateway', KEY_A, audience='status')
    at_taskmgr = sender('gateway', KEY_A, audience='taskmgr')

    with pytest.raises(FramingError) as excinfo:
        at_taskmgr.unwrap(to_status.wrap(BODY))
    assert 'not signed for this service' in str(excinfo.value)


def test_a_matching_audience_round_trips():
    a = sender('gateway', KEY_A, audience='status')
    b = sender('gateway', KEY_A, audience='status')
    assert b.unwrap(a.wrap(BODY)).principal == 'gateway'


def test_binding_on_one_end_only_is_refused():
    """Otherwise a peer could opt out of the binding by leaving it unset."""
    bound = sender('gateway', KEY_A, audience='status')
    unbound = sender('gateway', KEY_A)

    with pytest.raises(FramingError):
        bound.unwrap(unbound.wrap(BODY))
    with pytest.raises(FramingError):
        unbound.unwrap(bound.wrap(BODY))


def test_the_audience_never_travels():
    """Each end mixes in its own, so there is nothing on the wire to edit."""
    wrapped = sender('gateway', KEY_A, audience='status').wrap(BODY)
    assert b'status' not in wrapped


def test_two_services_of_equal_name_length_are_still_distinguished():
    """Only the length is on the wire, so names of the same length must be
    separated by the MAC itself."""
    a = sender('gateway', KEY_A, audience='aaaaaa')
    b = sender('gateway', KEY_A, audience='bbbbbb')
    with pytest.raises(FramingError) as excinfo:
        b.unwrap(a.wrap(BODY))
    assert 'does not match' in str(excinfo.value)


def test_an_audience_too_long_to_bind():
    with pytest.raises(ValueError):
        Signature(KEY_A, audience='x' * 256)


def test_a_truncated_signature_section():
    f = Framing(layers=[Signature({'status': KEY_A})])
    wrapped = bytearray(f.wrap(BODY))
    # Claim a longer key id than the section can hold.
    wrapped[_ID_AT - 2] = 250
    with pytest.raises(FramingError) as excinfo:
        f.unwrap(bytes(wrapped))
    assert 'truncated' in str(excinfo.value), \
        "it should say what is wrong, not blame the key it mis-read"


# ------------------------------------------------------------- replay --

def test_a_captured_message_can_be_sent_again_by_default():
    """Stated so the default is a decision, not an oversight: the timestamp
    bounds the window, it does not close it."""
    f = Framing(layers=[Signature(KEY_A)])
    wrapped = f.wrap(BODY)
    assert f.unwrap(wrapped).payload == BODY
    assert f.unwrap(wrapped).payload == BODY


def test_a_remembered_nonce_is_refused_the_second_time():
    f = Framing(layers=[Signature(KEY_A, replay_cache=1000)])
    wrapped = f.wrap(BODY)
    assert f.unwrap(wrapped).payload == BODY

    with pytest.raises(FramingError) as excinfo:
        f.unwrap(wrapped)
    assert 'already been delivered' in str(excinfo.value)


def test_distinct_messages_are_all_accepted():
    """The cache must reject repeats, not traffic."""
    f = Framing(layers=[Signature(KEY_A, replay_cache=1000)])
    for _ in range(50):
        assert f.unwrap(f.wrap(BODY)).payload == BODY


def test_the_same_body_twice_is_not_a_replay():
    """Two genuine calls with identical arguments are ordinary; only the
    same nonce is a replay."""
    f = Framing(layers=[Signature(KEY_A, replay_cache=1000)])
    assert f.unwrap(f.wrap(BODY)).payload == BODY
    assert f.unwrap(f.wrap(BODY)).payload == BODY


def test_a_replay_cache_needs_a_bound():
    with pytest.raises(ValueError) as excinfo:
        Signature(KEY_A, max_age=None, replay_cache=100)
    assert 'max_age' in str(excinfo.value)


def test_a_full_cache_shortens_the_window_rather_than_refusing_traffic():
    """When it overflows something has to give.  Dropping the oldest
    memories keeps honest calls working, and says so, rather than growing
    without limit or failing closed on legitimate traffic."""
    layer = Signature(KEY_A, replay_cache=4)
    f = Framing(layers=[layer])

    first = f.wrap(BODY)
    f.unwrap(first)
    for _ in range(10):
        f.unwrap(f.wrap(BODY))

    assert layer._replay.overflows > 0, "the cache should report the squeeze"
    assert f.unwrap(first).payload == BODY, \
        "the oldest nonce was forgotten, as documented"


def test_two_senders_drawing_the_same_nonce_do_not_collide():
    """The token is per key, so one service cannot lock another out by
    happening to pick the same random bytes."""
    from tinyrpc.layers import _ReplayCache
    cache = _ReplayCache(window=60.0, capacity=100)
    assert not cache.seen(b'status' + b'12345678')
    assert not cache.seen(b'taskmgr' + b'12345678')
    assert cache.seen(b'status' + b'12345678')


# ------------------------------------------------------------ ed25519 --

def test_a_verifier_needs_no_power_to_forge():
    """The whole point against HMAC: the end that checks status's messages
    holds only a public key, so compromising it does not let anyone speak
    as status."""
    private, public = generate_signing_key()
    status = Framing(layers=[Ed25519Signature({'status': public},
                                              signing_key=private)])
    verifier = Framing(layers=[Ed25519Signature({'status': public})])

    assert verifier.unwrap(status.wrap(BODY)).principal == 'status'
    with pytest.raises(FramingError) as excinfo:
        verifier.wrap(BODY)
    assert 'only' in str(excinfo.value) and 'verify' in str(excinfo.value)


def test_a_verifier_may_hold_many_public_keys_without_choosing_one():
    """A name service listing every service has no identity of its own to
    pick, so it must not be asked to."""
    _p1, pub1 = generate_signing_key()
    _p2, pub2 = generate_signing_key()
    verifier = Ed25519Signature({'status': pub1, 'taskmgr': pub2})
    assert verifier._sign_key is None


def test_each_service_arrives_as_itself():
    priv_s, pub_s = generate_signing_key()
    priv_t, pub_t = generate_signing_key()
    table = {'status': pub_s, 'taskmgr': pub_t}
    end = Framing(layers=[Ed25519Signature(table)])

    status = Framing(layers=[Ed25519Signature(table, sign_as='status',
                                              signing_key=priv_s)])
    taskmgr = Framing(layers=[Ed25519Signature(table, sign_as='taskmgr',
                                               signing_key=priv_t)])
    assert end.unwrap(status.wrap(BODY)).principal == 'status'
    assert end.unwrap(taskmgr.wrap(BODY)).principal == 'taskmgr'


def test_holding_one_private_key_does_not_let_you_sign_as_another():
    priv_s, pub_s = generate_signing_key()
    _priv_t, pub_t = generate_signing_key()
    table = {'status': pub_s, 'taskmgr': pub_t}

    with pytest.raises(ValueError) as excinfo:
        Ed25519Signature(table, sign_as='taskmgr', signing_key=priv_s)
    assert 'does not match' in str(excinfo.value)


def test_a_key_pair_that_does_not_go_together_is_caught_at_setup():
    """Rather than as unexplained verification failures on every message."""
    priv, _pub = generate_signing_key()
    _other, other_pub = generate_signing_key()
    with pytest.raises(ValueError):
        Ed25519Signature({'status': other_pub}, signing_key=priv)


def test_ed25519_refuses_a_tampered_body():
    private, public = generate_signing_key()
    f = Framing(layers=[Ed25519Signature({'status': public},
                                         signing_key=private)])
    wrapped = bytearray(f.wrap(BODY))
    wrapped[-1] ^= 0xFF
    with pytest.raises(FramingError) as excinfo:
        f.unwrap(bytes(wrapped))
    assert 'does not match' in str(excinfo.value)


def test_ed25519_refuses_an_unknown_signer():
    _priv_known, pub_known = generate_signing_key()
    priv_other, pub_other = generate_signing_key()
    stranger = Framing(layers=[Ed25519Signature({'stranger': pub_other},
                                                signing_key=priv_other)])
    end = Framing(layers=[Ed25519Signature({'status': pub_known})])
    with pytest.raises(FramingError) as excinfo:
        end.unwrap(stranger.wrap(BODY))
    assert 'stranger' in str(excinfo.value)


def test_ed25519_inherits_the_audience_binding():
    private, public = generate_signing_key()
    to_status = Framing(layers=[Ed25519Signature(
        {'gw': public}, signing_key=private, audience='status')])
    at_taskmgr = Framing(layers=[Ed25519Signature(
        {'gw': public}, audience='taskmgr')])
    with pytest.raises(FramingError) as excinfo:
        at_taskmgr.unwrap(to_status.wrap(BODY))
    assert 'not signed for this service' in str(excinfo.value)


def test_ed25519_inherits_the_freshness_check():
    private, public = generate_signing_key()
    f = Framing(layers=[Ed25519Signature({'status': public},
                                         signing_key=private,
                                         max_age=0.0001)])
    wrapped = f.wrap(BODY)
    time.sleep(0.01)
    with pytest.raises(FramingError) as excinfo:
        f.unwrap(wrapped)
    assert 'old' in str(excinfo.value)


def test_ed25519_survives_the_other_layers():
    private, public = generate_signing_key()
    layers = [Deflate(), Encrypt(KEY),
              Ed25519Signature({'status': public}, signing_key=private)]
    f = Framing(layers=layers)
    got = f.unwrap(f.wrap(b'z' * 5000))
    assert got.payload == b'z' * 5000
    assert got.principal == 'status'


def test_generate_signing_key_gives_a_matched_pair():
    private, public = generate_signing_key()
    assert len(private) == 32 and len(public) == 32
    assert generate_signing_key()[0] != private, "must not be deterministic"


def test_one_service_cannot_lock_another_out_by_picking_its_nonce(monkeypatch):
    """Make every nonce identical, so only the key id separates them.  If
    the token ignored the key id, taskmgr's first message would be refused
    as a replay of status's."""
    monkeypatch.setattr('tinyrpc.layers.os.urandom', lambda n: b'\x01' * n)

    end = Framing(layers=[Signature({'status': KEY_A, 'taskmgr': KEY_B},
                                    sign_as='status', replay_cache=1000)])
    status = Framing(layers=[Signature({'status': KEY_A})])
    taskmgr = Framing(layers=[Signature({'taskmgr': KEY_B})])

    assert end.unwrap(status.wrap(BODY)).principal == 'status'
    assert end.unwrap(taskmgr.wrap(BODY)).principal == 'taskmgr'

    with pytest.raises(FramingError):
        end.unwrap(status.wrap(BODY))


def test_a_nonce_is_remembered_across_the_generation_roll():
    """A nonce recorded just before the older generation is retired must
    still be refused after it, or the window is half what it says."""
    from tinyrpc.layers import _ReplayCache
    cache = _ReplayCache(window=0.05, capacity=100)

    assert not cache.seen(b'token')
    time.sleep(0.06)
    assert cache.seen(b'token'), "forgotten a whole generation too early"
    time.sleep(0.12)
    assert not cache.seen(b'token'), "should age out eventually"


def test_ed25519_verifies_when_the_audience_matches():
    """The negative test alone would pass even if signing quietly left the
    audience out; this is what says it goes in."""
    private, public = generate_signing_key()
    a = Framing(layers=[Ed25519Signature({'gw': public}, signing_key=private,
                                         audience='status')])
    b = Framing(layers=[Ed25519Signature({'gw': public}, audience='status')])
    assert b.unwrap(a.wrap(BODY)).principal == 'gw'


def test_ed25519_distinguishes_services_of_equal_name_length():
    """Only the length is on the wire, so equal-length names must be told
    apart by the signature itself."""
    private, public = generate_signing_key()
    a = Framing(layers=[Ed25519Signature({'gw': public}, signing_key=private,
                                         audience='aaaaaa')])
    b = Framing(layers=[Ed25519Signature({'gw': public}, audience='bbbbbb')])
    with pytest.raises(FramingError) as excinfo:
        b.unwrap(a.wrap(BODY))
    assert 'does not match' in str(excinfo.value)


# ------------------------------------------ what this end cannot undo --

def test_a_body_this_end_cannot_decompress_is_refused():
    """Regression.  unwrap() walked the layers it *had* and ignored the flags
    it did not, so a receiver missing Deflate handed back a payload still
    compressed -- as if it were the body, with nothing to say otherwise."""
    sender = Framing(layers=[Deflate(threshold=0)])
    receiver = Framing()

    with pytest.raises(FramingError) as excinfo:
        receiver.unwrap(sender.wrap(BODY))
    assert 'no layer' in str(excinfo.value)


def test_a_body_this_end_cannot_decrypt_is_refused():
    sender = Framing(layers=[Encrypt(KEY)])
    with pytest.raises(FramingError):
        Framing().unwrap(sender.wrap(BODY))


def test_a_signature_this_end_cannot_check_is_not_an_error():
    """Different case, and deliberately so: the body is intact, it is only
    unverified.  Whether that is acceptable is what `require` decides, so a
    receiver that asks for nothing gets the message."""
    signed = Framing(layers=[Signature(KEY_A)])
    lax = Framing()

    got = lax.unwrap(signed.wrap(BODY))
    assert got.payload == BODY
    assert got.principal is None, "and it knows it proved nothing"


def test_a_receiver_that_requires_a_signature_still_refuses_one():
    strict = Framing(layers=[Signature(KEY_A)], require=FLAG_SIGNED)
    with pytest.raises(PolicyError):
        strict.unwrap(Framing().wrap(BODY))
