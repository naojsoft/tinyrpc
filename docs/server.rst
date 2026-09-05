Server implementations
======================

Like :doc:`client`, servers are top-level instances that most user code should
interact with. They provide runnable functions that are combined with
transports, protocols and dispatchers to form a complete RPC system.

.. automodule:: tinyrpc.server
   :members:
   :noindex:

Authenticating a caller
-----------------------

:py:attr:`~tinyrpc.server.RPCServer.authenticator` runs after a message is
parsed and before the dispatcher is asked to handle it; raising from it refuses
the call, and the exception becomes an error response like any other.

It lives on the server rather than in the protocol or the dispatcher because it
is the one place that can see both what the transport knows about the caller and
what the protocol made of the request -- so the same policy keeps working when
either is swapped out.

.. code-block:: python

    def only_from_localhost(context, request):
        host, _port = context.client_address
        if host != '127.0.0.1':
            raise PermissionError('go away')

    server.authenticator = only_from_localhost

What ``context`` holds is up to the transport;
:py:class:`~tinyrpc.transports.http_server.HttpServerTransport` provides
``client_address`` and the parsed HTTP Basic ``auth``. A protocol built on
:doc:`framing` puts what it knows on the *request* instead, which travels over
any transport: see :doc:`flexrpc`.

Implementations
---------------

.. autoclass:: tinyrpc.server.executor.RPCServerExecutor
   :members:
   :noindex:
   :show-inheritance:

.. autoclass:: tinyrpc.server.AsyncioRPCServer
   :members:
   :noindex:
   :show-inheritance:

.. py:class:: tinyrpc.server.gevent.RPCServerGreenlets

   Asynchronous RPCServer.

   This implementation of :py:class:`~tinyrpc.server.RPCServer` uses
   :py:func:`gevent.spawn` to spawn new client handlers, result in asynchronous
   handling of clients using greenlets.
