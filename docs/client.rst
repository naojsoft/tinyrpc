RPC Client
==========

:py:class:`~tinyrpc.client.RPCClient` instances are high-level handlers for
making remote procedure calls to servers. Other than
:py:class:`~tinyrpc.client.RPCProxy` objects, they are what most user
applications interact with.

Clients needs to be instantiated with a protocol and a transport to function.
Proxies are syntactic sugar for using clients.

.. autoclass:: tinyrpc.client.RPCClient
    :members:
    :show-inheritance:
    :noindex:

.. autoclass:: tinyrpc.client.RPCProxy
    :members:
    :show-inheritance:
    :noindex:

.. automodule:: tinyrpc.client
    :members: RPCCall, RPCCallTo
    :show-inheritance:
    :noindex:


Keeping several calls in flight
-------------------------------

:py:class:`~tinyrpc.client.RPCClient` sends a call and waits for its reply, so
the next call cannot start until this one finishes.
:py:class:`~tinyrpc.client_multiplexing.MultiplexingRPCClient` holds one
connection open and tells replies apart by the correlation id the protocol puts
on them, so calls overlap: ten calls that each take a second take a second
between them rather than ten.

It needs a transport that holds its connection open -- a
:py:class:`~tinyrpc.transports.NonBlockingClientTransport` -- and a protocol
whose replies carry that id. It refuses a protocol whose
:py:attr:`~tinyrpc.protocols.RPCProtocol.supports_reply_correlation` is false,
which is how XML-RPC is kept out: it has no id field, so a reply is matched to
its request by ordering alone and only one call can be outstanding.

.. code-block:: python

    pending = [client.begin_call('work', (n,), None) for n in jobs]
    results = [client.collect(p) for p in pending]

For ordinary request/response traffic the plain client is simpler and gives up
nothing, since it holds no connection to go stale.

.. autoclass:: tinyrpc.client_multiplexing.MultiplexingRPCClient
    :members:
    :show-inheritance:
    :noindex:

.. autoclass:: tinyrpc.client_multiplexing.PendingCall
    :members:
    :show-inheritance:
    :noindex:
