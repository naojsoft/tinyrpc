FlexRPC
=======

XML-RPC, JSON-RPC and msgpack-RPC each fix their encoding, and none of them says
anything about who is calling: the specification *is* the encoding, and
authentication is left to whatever the transport happens to offer -- which for
HTTP means a password in a header, and for a raw socket means nothing at all.

FlexRPC separates the three decisions that are usually welded together:

* **how the body is encoded** is a :doc:`serializer <flexrpc>` choice -- msgpack
  where it is machine to machine, json where a person may have to read it --
  recorded in the envelope, so a server answers in the encoding it was addressed
  in without being configured to;
* **what protects the message** is a :doc:`framing` choice -- signing,
  encryption, compression, credentials, in whatever combination -- and a
  receiver states what it *requires*, so a peer cannot opt out of it;
* **how the bytes get there** is the transport, unchanged and unaware of either.

It is not a standard, and no third party speaks it. It is for traffic between
components you control on both ends.

A first call
------------

.. code-block:: python

    from tinyrpc.protocols.flexrpc import FlexRPCProtocol

    protocol = FlexRPCProtocol()          # msgpack, no protection

Everything else on this page is a parameter to that.

.. code-block:: python

    from tinyrpc.client import RPCClient
    from tinyrpc.transports.tcp import ConnectionlessTcpClientTransport

    client = RPCClient(FlexRPCProtocol(),
                       ConnectionlessTcpClientTransport(('localhost', 8080)))
    client.get_proxy().echo('hi', loud=True)

Keyword arguments are carried natively, which XML-RPC cannot do. Every request
carries a correlation id and every reply echoes it, so several calls can be in
flight on one connection and
:py:class:`~tinyrpc.client_multiplexing.MultiplexingRPCClient` works over it.

Choosing an encoding
--------------------

.. code-block:: python

    FlexRPCProtocol('json')            # readable, and reachable from elsewhere
    FlexRPCProtocol('msgpack')         # compact and fast (the default)
    FlexRPCProtocol('msgpack-numpy')   # arrays as buffers, not lists of numbers

The envelope records which was used, so the two ends need not agree in advance:

.. code-block:: python

    caller = FlexRPCProtocol('json')
    service = FlexRPCProtocol('msgpack')

    request = service.parse_request(caller.create_request('echo', ['hi']).serialize())
    reply = request.respond('HI')      # goes back as json, because that arrived

.. warning::

    msgpack is compact and fast *when its C extension is installed*, and it
    silently falls back to a pure-Python implementation when it is not. On one
    120-key mapping the extension packs in 8.2µs, the fallback in 187µs, and
    :py:mod:`json` in 32µs -- so a deployment that picked msgpack for speed and
    got the fallback chose the slowest option available to it. Check with
    ``python -c "import msgpack; print(msgpack._cmsgpack)"``; it raises
    ``AttributeError`` for the fallback.

Oversized integers
++++++++++++++++++

msgpack stops at 64 bits where json and XML do not, so without help the choice
of encoding would quietly change what a program may send. Integers too large for
msgpack travel as an extension type holding their decimal text, so the same
values cross whichever encoding is picked.

Registering your own
++++++++++++++++++++

.. code-block:: python

    from tinyrpc import serializers

    serializers.register('cbor', serializers.SERIALIZER_LOCAL,
                         cbor2.dumps, cbor2.loads)

    protocol = FlexRPCProtocol('cbor')

The id is what travels, so both ends must agree on it and it must not change
once anything has spoken it. Ids from
:py:data:`~tinyrpc.serializers.SERIALIZER_LOCAL` (128) upwards are never
assigned by ``tinyrpc``.

Note what is deliberately absent: pickle. Unpickling runs whatever it is sent,
which is not a property to offer a peer over a socket.

Protecting a call
-----------------

Pass a :doc:`framing`. Everything on that page applies here unchanged.

.. code-block:: python

    from tinyrpc.framing import FLAG_SIGNED, Framing
    from tinyrpc.layers import Deflate, Signature

    keys = {'status': status_key, 'taskmgr': taskmgr_key}

    # the service
    FlexRPCProtocol('msgpack', framing=Framing(
        layers=[Deflate(), Signature(keys, sign_as='taskmgr', audience='taskmgr')],
        require=FLAG_SIGNED))

    # a caller
    FlexRPCProtocol('msgpack', framing=Framing(
        layers=[Deflate(), Signature(keys, sign_as='status', audience='taskmgr')]))

Both ends need the same *layers*, even where only one end needs the same
*policy*. A caller whose framing lacks ``Deflate`` will be refused -- it cannot
undo what the reply did to the body, and being told so is better than being
handed something it never decompressed. A caller that merely does not
``require`` a signature is fine: an unverifiable signature leaves the body
readable, so that is a policy question rather than a can-I-read-this one. This
is why building the framing in one function, as the :ref:`walkthrough
<new-rpc-variant>` below does, is worth the trouble.

Knowing who called
------------------

A parsed request carries both what was proven and what was merely claimed:

.. code-block:: python

    request.principal    # set by the framing when a signature verified
    request.credentials  # a Credentials the sender sent, unverified
    request.signed_as    # which key verified it

:py:attr:`~tinyrpc.server.RPCServer.authenticator` is where a service acts on
that. It runs after the message is parsed and before the dispatcher sees it, and
raising from it refuses the call:

.. code-block:: python

    from tinyrpc.protocols.flexrpc import require_principal

    server.authenticator = require_principal('status', 'gateway')

:py:func:`~tinyrpc.protocols.flexrpc.require_principal` looks at the principal
and never at the credentials, which is the whole point: a caller can put any
name it likes in the second. Writing your own is the same shape:

.. code-block:: python

    def only_status_may_write(context, request):
        if request.method.startswith('set_') and request.principal != 'status':
            raise PermissionError('%s may not write' % (request.principal,))

The hook lives on the server rather than in the protocol or the dispatcher
because it is the one place that can see both what the transport knows about the
caller -- ``context.client_address``, for instance -- and what the protocol made
of the request.

Errors
------

Errors are a distinct message type rather than a value that might be mistaken
for a result, and carry the numeric codes from the XML-RPC fault code
interoperability table that JSON-RPC 2.0 also adopted, so one table explains
every protocol here.

==========================  ======  ================================
constant                    code    meaning
==========================  ======  ================================
``ERROR_PARSE``             -32700  the body could not be decoded
``ERROR_INVALID_REQUEST``   -32600  it decoded, but is not a request
``ERROR_METHOD_NOT_FOUND``  -32601  no such method
``ERROR_INVALID_PARAMS``    -32602  wrong arguments for it
``ERROR_INTERNAL``          -32603  the machinery failed
``ERROR_APPLICATION``       -32500  the method itself raised
``ERROR_REFUSED``           -32001  it did not survive the envelope
==========================  ======  ================================

``ERROR_REFUSED`` covers a signature that did not verify, a peer that omitted
protection this end requires, and an authenticator that said no. Such a reply
cannot echo a correlation id -- whatever the message claimed, it did not survive
the envelope, so there is nothing there to trust.

.. _new-rpc-variant:

Building a new RPC variant
--------------------------

Suppose a telescope's instrument network needs its own dialect: CBOR on the
wire, compressed, signed with per-instrument keys, refusing anything unsigned,
and rejecting replays. Nothing below subclasses anything.

**1. Register the encoding.** Only if it is not one of the three already there.

.. code-block:: python

    import cbor2
    from tinyrpc import serializers

    CBOR = serializers.SERIALIZER_LOCAL + 1
    serializers.register('cbor', CBOR, cbor2.dumps, cbor2.loads)

**2. Say what protects a message.** One function, so both ends cannot drift
apart -- which is the usual way a deployment breaks.

.. code-block:: python

    from tinyrpc.framing import FLAG_SIGNED, Framing
    from tinyrpc.layers import Deflate, Signature

    INSTRUMENT_KEYS = {
        'spectrograph': b'...32 bytes...',
        'guider':       b'...32 bytes...',
        'sequencer':    b'...32 bytes...',
    }

    def instrument_framing(me, talking_to, strict=True):
        return Framing(
            layers=[Deflate(threshold=512),
                    Signature(INSTRUMENT_KEYS, sign_as=me,
                              audience=talking_to,
                              max_age=60.0, replay_cache=50000)],
            require=FLAG_SIGNED if strict else 0)

Note the asymmetry, which is deliberate: a service is ``strict`` and refuses
anything unsigned, while a caller need not refuse an unsigned *reply*. The
sender is the one with something to prove, and being lenient in the other
direction means turning authentication on at one end does not break the other.

**3. Name the dialect.**

.. code-block:: python

    from tinyrpc.protocols.flexrpc import FlexRPCProtocol

    def instrument_protocol(me, talking_to, strict=True):
        return FlexRPCProtocol('cbor',
                               framing=instrument_framing(me, talking_to, strict))

**4. Serve it,** over any transport. The transport neither knows nor cares.

.. code-block:: python

    import socket
    from concurrent.futures import ThreadPoolExecutor

    from tinyrpc.dispatch import RPCDispatcher
    from tinyrpc.protocols.flexrpc import require_principal
    from tinyrpc.server.executor import RPCServerExecutor
    from tinyrpc.transports.tcp import ConnectionlessTcpServerTransport

    dispatcher = RPCDispatcher()
    dispatcher.add_method(expose_frame, 'expose')

    listening = socket.socket()
    listening.bind(('', 9010))
    listening.listen(16)

    server = RPCServerExecutor(
        ConnectionlessTcpServerTransport(listening, poll_timeout=0.2),
        instrument_protocol('sequencer', 'sequencer'),
        dispatcher,
        ThreadPoolExecutor(max_workers=8))
    server.authenticator = require_principal('spectrograph', 'guider')
    server.start()

**5. Call it.**

.. code-block:: python

    from tinyrpc.client import RPCClient
    from tinyrpc.transports.tcp import ConnectionlessTcpClientTransport

    client = RPCClient(
        instrument_protocol('guider', 'sequencer', strict=False),
        ConnectionlessTcpClientTransport(('sequencer-host', 9010)))

    client.get_proxy().expose(seconds=1.5, filter='Ha')

What that bought, and where each piece came from:

* CBOR on the wire, because a serializer was registered and named;
* compressed above 512 bytes, from a layer;
* every call proved to come from a named instrument, from a layer, and refused
  if not, from ``require``;
* no call usable at a service it was not addressed to, from ``audience``;
* no call replayable, from ``max_age`` and ``replay_cache``;
* only two instruments allowed to expose, from the authenticator;
* over TCP, and swapping to 0mq or HTTP changes only step 4 and 5.

Going further
+++++++++++++

A genuinely new *shape* of message -- not just a new encoding or a different
mixture of protection -- means a protocol class rather than a configuration of
this one. :doc:`protocols` describes that interface, and
:py:mod:`tinyrpc.protocols.flexrpc` is a worked example of implementing it: it
is about 400 lines, most of them the error table.

If the new thing is a way of *protecting* messages rather than of structuring
them, write a :py:class:`~tinyrpc.framing.Layer` instead -- three methods, and
every protocol built on the framing gets it.

API reference
-------------

.. autoclass:: tinyrpc.protocols.flexrpc.FlexRPCProtocol
    :members:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.protocols.flexrpc.FlexRPCRequest
    :members:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.protocols.flexrpc.FlexRPCResponse
    :members:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.protocols.flexrpc.FlexRPCErrorResponse
    :members:
    :show-inheritance:
    :member-order: bysource

.. autofunction:: tinyrpc.protocols.flexrpc.require_principal

.. autoexception:: tinyrpc.protocols.flexrpc.FlexRPCError
    :show-inheritance:

Serializers
+++++++++++

.. automodule:: tinyrpc.serializers
    :members:
    :member-order: bysource
