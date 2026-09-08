Transports
==========

Transports are somewhat low level interface concerned with transporting
messages across through different means. "Messages" in this case are simple
strings. All transports need to support two different interfaces:

.. autoclass:: tinyrpc.transports.ServerTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.transports.ClientTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.transports.NonBlockingClientTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

.. autoexception:: tinyrpc.transports.TransportTimeout
    :show-inheritance:

Note that these transports are of relevance when using ``tinyrpc``-built in
facilities. They can be coopted for any other purpose, if you simply need
reliable server-client message passing as well.

A client transport blocks by default: it sends, and waits for the reply. Three
things exist for when that is not what you want.
:py:class:`~tinyrpc.transports.NonBlockingClientTransport` splits sending from
collecting, which is what
:py:class:`~tinyrpc.client_multiplexing.MultiplexingRPCClient` uses to keep
several calls in flight over one connection. The ``Asyncio*`` transports below
are the same idea for code that is already using :py:mod:`asyncio`. And monkey
patching with gevent still works for simple cases.

A server transport that blocks forever waiting for the next request cannot be
shut down, because setting an event does nothing until a request happens to
arrive. Transports that poll raise
:py:exc:`~tinyrpc.transports.TransportTimeout` instead, which is how a serve
loop gets the chance to notice it has been asked to stop.


Transport implementations
-------------------------

A few transport implementations are included with ``tinyrpc``:

0mq
~~~

Based on :py:mod:`zmq`, supports 0mq based sockets. Highly recommended:

.. autoclass:: tinyrpc.transports.zmq.ZmqServerTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.transports.zmq.ZmqClientTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

HTTP
~~~~

.. autoclass:: tinyrpc.transports.http_server.HttpServerTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.transports.http_client.HttpClientTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

:py:class:`~tinyrpc.transports.http.HttpPostClientTransport` is the older client,
built on :py:mod:`requests`. It still works; ``HttpClientTransport`` above uses
:py:mod:`http.client` from the standard library instead, which needs no
dependency and costs about a millisecond less per call.

.. autoclass:: tinyrpc.transports.http.HttpPostClientTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

.. note:: To set a timeout on your client transport provide a ``timeout``
    keyword parameter like::

        transport = HttpPostClientTransport(endpoint, timeout=0.1)

    It will result in a ``requests.exceptions.Timeout`` exception when a
    timeout occurs.

TCP
~~~

A protocol carried straight over a socket, with no HTTP framing. Cheaper per
call than the HTTP carrier; it cannot carry an HTTP header, so a protocol
needing to identify its caller over one wants :doc:`framing`.

Messages are length-prefixed by :py:class:`~tinyrpc.transports.tcp.TransportPackerRobust`,
so a message larger than one read arrives whole and two small ones do not arrive
as one.

.. autoclass:: tinyrpc.transports.tcp.ConnectionlessTcpServerTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.transports.tcp.ConnectionlessTcpClientTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

The connectionless pair dials once per call, which is what lets a client and a
service be restarted in any order: there is no held connection to go stale. The
pair below holds one open, which is cheaper per call and the only shape that can
multiplex -- in exchange the connection can die, so the client dials again.

.. autoclass:: tinyrpc.transports.tcp.TcpServerTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.transports.tcp.NonBlockingTcpClientTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

Framing, and talking to something that is not tinyrpc
+++++++++++++++++++++++++++++++++++++++++++++++++++++

The packer *is* the wire format, on a server exactly as on a client. Both ends
have to be given the same one, and neither can find out what the other chose --
a mismatch does not raise, it times out.

The default, :py:func:`~tinyrpc.transports.tcp.default_packer`, prefixes each
message with its length. That prefix is a ``tinyrpc`` extension: standard
msgpack-RPC over TCP has none, because the msgpack stream is self-delimiting.
To speak the standard format, say so at both ends:

.. code-block:: python

    from tinyrpc.transports.tcp import (TcpServerTransport,
                                        TcpClientTransport, TransportPacker)

    server = TcpServerTransport(sock, packer=TransportPacker())
    client = TcpClientTransport((host, port), packer=TransportPacker())

That works for every transport here, connectionless or stateful. What it costs
is the reason the prefix is the default: without a length there is nothing to
say where a message ends, so the protocol is handed whatever one ``recv()``
returned. Messages that fit in one read are fine -- which is most RPC traffic,
and why the unframed format works at all -- and a larger one arrives in pieces
and fails to parse.

:py:class:`~tinyrpc.transports.tcp.UnframedTcpClientTransport` is the one
transport whose default is unframed, for exactly that case. It is otherwise
:py:class:`~tinyrpc.transports.tcp.NonBlockingTcpClientTransport` -- one held
connection, re-dialled when it drops -- and was formerly called
``AsyncTcpClientTransport``, which said what it is not: it is threaded, not
:py:mod:`asyncio`.

.. autoclass:: tinyrpc.transports.tcp.UnframedTcpClientTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

.. autofunction:: tinyrpc.transports.tcp.default_packer

asyncio
~~~~~~~

.. autoclass:: tinyrpc.transports.tcp.AsyncioTcpServerTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.transports.tcp.AsyncioTcpClientTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

Served by :py:class:`~tinyrpc.server.AsyncioRPCServer`, which awaits a handler
that returns a coroutine and can hand a blocking one to an executor.

WSGI
~~~~

.. autoclass:: tinyrpc.transports.wsgi.WsgiServerTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

CGI
~~~

.. autoclass:: tinyrpc.transports.cgi.CGIServerTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

Callback
~~~~~~~~

.. autoclass:: tinyrpc.transports.callback.CallbackServerTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

RabbitMQ
~~~~~~~~

.. autoclass:: tinyrpc.transports.rabbitmq.RabbitMQServerTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.transports.rabbitmq.RabbitMQClientTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

WebSocket
~~~~~~~~~

.. autoclass:: tinyrpc.transports.websocket.WSServerTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.transports.websocket.WSApplication
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

.. autoclass:: tinyrpc.transports.websocketclient.HttpWebSocketClientTransport
    :members:
    :noindex:
    :show-inheritance:
    :member-order: bysource

