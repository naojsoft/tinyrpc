The framing layer
=================

Compression, encryption and authentication are the same shape: each transforms
the bytes between the protocol and the transport, and each needs a little
metadata carried alongside so the far end can undo it. ``tinyrpc`` gives them
one envelope rather than letting each invent a wrapper.

Framing is entirely optional. A protocol that does not want it does not pay for
it, and the protocols that predate it -- JSON-RPC, msgpack-RPC, XML-RPC -- do
not use it at all. :doc:`flexrpc` is built on it.

Where it sits
-------------

::

    dispatcher
        |
    protocol      method, args, kwargs  <->  a body of bytes
        |
    framing       the body  <->  header + sections + body      <-- this page
        |
    transport     bytes on a wire

The envelope
------------

The header is fixed and binary: ten bytes, packed with :py:mod:`struct`.

::

    magic(2)  version(1)  flags(1)  serializer(1)  protocol(1)  length(4)

The flags say which optional sections follow. When nothing is enabled the flags
are zero, the header is all there is, and the body is the payload verbatim --
so an unsecured message costs one ``struct.pack`` and one ``struct.unpack``,
about 0.2µs the pair, and ten bytes on the wire.

Two of those bytes belong to the protocol rather than to the framing.
``serializer`` says how the body was encoded, which is what lets a server answer
in the encoding it was addressed in. ``protocol`` is a byte the protocol owns
outright, carried here and never interpreted; :doc:`flexrpc` uses it to version
the shape of its own body, which is what a second, nested envelope would
otherwise have been for.

Layers
------

A layer transforms the payload on the way out and undoes it on the way in. The
order matters, and the reason for each is worth knowing:

.. code-block:: python

    from tinyrpc.framing import Framing
    from tinyrpc.layers import Deflate, Encrypt, Signature

    framing = Framing(layers=[Deflate(), Encrypt(key), Signature(keys)])

Compress **before** encrypting, because ciphertext does not compress. Sign
**last**, so that what is verified is what actually arrived. A receiver built
with the same layers in the same order unwinds them backwards.

Compression
+++++++++++

:py:class:`~tinyrpc.layers.Deflate` compresses with :py:mod:`zlib`. Payloads
below ``threshold`` -- 256 bytes by default -- are stored rather than
compressed, since compressing a short message usually makes it longer.

.. code-block:: python

    Framing(layers=[Deflate(level=6, threshold=256)])

The flag is still set for a stored payload, so the far end still calls
``remove()``. zlib round-trips a stored block fine, and a per-message decision
would otherwise need a header bit of its own.

Encryption
++++++++++

:py:class:`~tinyrpc.layers.Encrypt` uses NaCl's secret box, which authenticates
the message as well as hiding it. A fresh nonce is generated per message and
carried in its own section; reusing one with the same key would leak the
plaintext, so it is never derived from anything predictable.

.. code-block:: python

    from tinyrpc.layers import Encrypt, derive_key

    Framing(layers=[Encrypt(derive_key('a shared passphrase'))])

It authenticates the *message*, not the sender: anyone holding the key can
produce a valid box. With one key per pair of peers that is a useful statement;
with one key shared by everyone it is not. It therefore reports no principal --
identity is :py:class:`~tinyrpc.layers.Signature`'s job, and keeping that answer
in one place means there is never a doubt about which layer decided who the
caller is.

Requires ``pynacl``: ``pip install tinyrpc[nacl]``.

Authentication
--------------

Two shapes, answering different questions. Keeping them apart is the point.

Credentials: what the sender *claims*
+++++++++++++++++++++++++++++++++++++

:py:class:`~tinyrpc.framing.Credentials` carries a name and a secret. It is what
HTTP Basic authentication does. It is not a layer -- it transforms nothing, it
is just carried -- and it sends a reusable secret, so it is only as private as
the connection.

.. code-block:: python

    from tinyrpc.framing import Credentials

    wire = framing.wrap(body, credentials=Credentials('bob', 'sekrit').encode())

Signatures: what the sender *proves*
++++++++++++++++++++++++++++++++++++

:py:class:`~tinyrpc.layers.Signature` proves the sender holds a key without
sending it, and detects any change to the message on the way.

Keys have names, and the name travels so the far end knows which key to check
against. That is what makes identity per-service: with one secret shared by
everything, a valid signature proves only that the sender is somewhere inside
the trusted set, and any member of it can sign as any other. With a key per
service, a verified message names exactly one holder.

.. code-block:: python

    from tinyrpc.layers import Signature

    # a service that accepts two callers, and signs its replies as itself
    Signature({'status': key_a, 'taskmgr': key_b}, sign_as='status')

    # a key that speaks for a different principal: rotation, two names,
    # one identity
    Signature({'status-2024': (key_a, 'status')})

    # one unnamed shared secret: proves possession, names nobody
    Signature(shared_key)

The name is a claim, not proof: it only selects a key. A sender claiming to be
``taskmgr`` without taskmgr's key produces a signature that does not verify, and
the name is itself covered by the MAC, so it cannot be relabelled on a message
that does.

Proven and claimed, kept apart
++++++++++++++++++++++++++++++

:py:meth:`~tinyrpc.framing.Framing.unwrap` returns an
:py:class:`~tinyrpc.framing.Unwrapped`, which draws the distinction the design
turns on:

.. code-block:: python

    got = framing.unwrap(data)

    got.principal            # who the sender is *proven* to be, or None
    got.claimed_credentials  # what it *said*, unverified, or None
    got.is_authenticated     # asks about the first alone
    got.signed_as            # which key verified, where several map to one name

Only a layer can set ``principal``, and only after its check passed. Nothing a
sender writes can reach it. Handing both to a caller as "auth" invites treating
a carried password like a verified signature, which is why they are named apart.

Freshness, audience and replay
++++++++++++++++++++++++++++++

A signature covers a timestamp and a nonce, so a captured message stops working
once ``max_age`` -- 300 seconds by default -- has passed. That needs the two
clocks within roughly that much of each other.

It optionally covers an *audience*: the name of the service the connection
serves. The audience is never sent. Each end mixes in the value it was
configured with, so there is nothing on the wire to edit, and a request captured
on the way to one service will not verify at another, even from a peer that
legitimately talks to both. Both ends must agree, including on ``None``.

.. code-block:: python

    Signature(keys, sign_as='gateway', audience='status', max_age=300.0,
              replay_cache=100000)

``max_age`` bounds how long a captured message stays useful; it does not stop it
being sent again inside that window. ``replay_cache`` closes that, at the cost
of remembering that many recent nonces, and is off by default. When it fills,
the window shortens rather than either refusing honest traffic or growing
without limit -- and the layer counts that happening, since it means the window
is no longer the one configured.

Public keys, where verifying should not confer forging
++++++++++++++++++++++++++++++++++++++++++++++++++++++

HMAC's key is symmetric: whoever can check a signature can also produce one. On
a trusted network that is fine, but it means every service holding the key to
verify ``status`` can also *be* ``status``, and one compromised host forges for
everyone.

:py:class:`~tinyrpc.layers.Ed25519Signature` gives each service a private key
nobody else has and a public key that only checks. A name service holding
nothing but public keys cannot impersonate anything it lists.

.. code-block:: python

    from tinyrpc.layers import Ed25519Signature, generate_signing_key

    private, public = generate_signing_key()

    # the service itself
    Ed25519Signature(published_keys, sign_as='status', signing_key=private)

    # something that only verifies: a monitor, or a name service
    Ed25519Signature(published_keys)

Everything else is inherited -- wire format, key ids, freshness, audience
binding. Only the signature section changes, from a 32-byte MAC to a 64-byte
signature. Asymmetry costs about twelve times as much per call, which is why it
is offered rather than assumed.

A receiver states what it requires
----------------------------------

A receiver must not simply do whatever the header asks. A sender that declares
no signature and no credentials would otherwise walk straight past both checks.

.. code-block:: python

    from tinyrpc.framing import FLAG_SIGNED, Framing

    Framing(layers=[Signature(keys)], require=FLAG_SIGNED)

A message missing a required flag is refused with
:py:exc:`~tinyrpc.framing.PolicyError` whatever it claims. Requiring a layer the
framing has not been given is refused at construction, so a misconfiguration
fails once at startup rather than on every message.

Insisting that messages are *signed at all* is this. It is a different question
from *who signed them*, which is ``principal``: two questions, two mechanisms.

What it costs
-------------

Per round trip, measured on one machine with a small body:

===========================  ===========  =========
framing                       round trip  wire
===========================  ===========  =========
none (plain header)              0.74 µs     +10 B
HMAC signed                      6.22 µs     +58 B
HMAC signed, replay cache        6.65 µs     +58 B
Ed25519 signed                  71.75 µs     +90 B
compress + encrypt + sign       24.29 µs
===========================  ===========  =========

API reference
-------------

.. autoclass:: tinyrpc.framing.Framing
    :members:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.framing.Unwrapped
    :members:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.framing.Layer
    :members:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.framing.Credentials
    :members:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.layers.Deflate
    :members:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.layers.Encrypt
    :members:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.layers.Signature
    :members:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.layers.Ed25519Signature
    :members:
    :show-inheritance:
    :member-order: bysource

.. autofunction:: tinyrpc.layers.derive_key

.. autofunction:: tinyrpc.layers.generate_signing_key

.. autoexception:: tinyrpc.framing.FramingError
    :show-inheritance:

.. autoexception:: tinyrpc.framing.PolicyError
    :show-inheritance:

.. autoexception:: tinyrpc.framing.UnsupportedVersion
    :show-inheritance:
