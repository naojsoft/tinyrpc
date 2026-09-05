#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Server definition.

Defines and implements a single-threaded, single-process, synchronous server.
"""

# FIXME: needs (more) unittests
# FIXME: needs checks for out-of-order, concurrency, etc as attributes
import asyncio
import logging
from typing import Any, Callable

import tinyrpc.exc
from tinyrpc import RPCProtocol
from tinyrpc.dispatch import RPCDispatcher
from tinyrpc.transports import ServerTransport, TransportTimeout


logger = logging.getLogger(__name__)


def _is_coroutine_method(dispatcher: RPCDispatcher, request: Any) -> bool:
    """Whether the method a request names is defined with ``async def``."""
    try:
        return asyncio.iscoroutinefunction(
            dispatcher.get_method(request.method))
    except Exception:
        return False


class RPCServer(object):
    """High level RPC server.

    The server is completely generic only assuming some form of RPC communication is intended.
    Protocol, data transport and method dispatching are injected into the server object.

    :param transport: The data transport mechanism to use.
    :param protocol: The RPC protocol to use.
    :param dispatcher: The dispatching mechanism to use.
    :type transport: :py:class:`~tinyrpc.transports.ServerTransport`
    :type protocol: :py:class:`~tinyrpc.protocols.RPCProtocol`
    :type dispatcher: :py:class:`~tinyrpc.dispatch.RPCDispatcher`
    """

    trace = None
    """Trace incoming and outgoing messages.

    When this attribute is set to a callable this callable will be called directly
    after a message has been received and immediately after a reply is sent.
    The callable should accept three positional parameters:

    :param str direction: Either '-->' for incoming or '<--' for outgoing data.
    :param any context: The context returned by :py:meth:`~tinyrpc.transports.ServerTransport.receive_message`.
    :param bytes message: The message itself.

    Example:

    .. code-block:: python

        def my_trace(direction, context, message):
            logger.debug('%s%s', direction, message)

        server = RPCServer(transport, protocol, dispatcher)
        server.trace = my_trace
        server.serve_forever()

    will log all incoming and outgoing traffic of the RPC service.

    Note that the ``message`` will be the data stream that is transported,
    not the interpreted meaning of that data.
    It is therefore possible that the binary stream is unreadable without further translation.
    """
    authenticator = None
    """Authenticate and authorise a request before it is dispatched.

    When this attribute is set to a callable it is called after a message has
    been parsed but before the dispatcher is asked to handle it.  It should
    raise an exception to refuse the request; the exception is turned into an
    error response in the same way as one raised by the called method.

    The callable should accept two positional parameters:

    :param any context: The context returned by
        :py:meth:`~tinyrpc.transports.ServerTransport.receive_message`.
        What it holds is up to the transport;
        :py:class:`~tinyrpc.transports.http_server.HttpServerTransport`, for
        instance, provides ``client_address`` and ``auth``.
    :param request: The parsed :py:class:`~tinyrpc.protocols.RPCRequest`.

    Example:

    .. code-block:: python

        def only_from_localhost(context, request):
            host, _port = context.client_address
            if host != '127.0.0.1':
                raise PermissionError('go away')

        server = RPCServer(transport, protocol, dispatcher)
        server.authenticator = only_from_localhost

    Keeping this on the server rather than in the protocol or the dispatcher
    is deliberate: it is the one place that can see both what the transport
    knows about the caller and what the protocol made of the request, so the
    same policy works whichever of the two is swapped out.
    """
    logger = None
    """Where a failed handler is reported.

    Defaults to this module's logger.  A handler that raises is reported
    here rather than vanishing into a Future or a Task nobody reads.
    """
    def __init__(
            self, transport: ServerTransport, protocol: RPCProtocol,
            dispatcher: RPCDispatcher
    ) -> None:
        self.transport = transport
        self.protocol = protocol
        self.dispatcher = dispatcher
        self.trace = None
        self.authenticator = None
        self.logger = None

    def serve_forever(self) -> None:
        """Handle requests forever.

        Starts the server loop; continuously calling :py:meth:`receive_one_message`
        to process the next incoming request.
        """
        while True:
            self.receive_one_message()

    def receive_one_message(self) -> None:
        """Handle a single request.

        Polls the transport for a new message.

        After a new message has arrived :py:meth:`_spawn` is called with a handler
        function and arguments to handle the request.

        The handler function will try to decode the message using the supplied
        protocol, if that fails, an error response will be sent. After decoding
        the message, the dispatcher will be asked to handle the resulting
        request and the return value (either an error or a result) will be sent
        back to the client using the transport.
        """
        context, message = self.transport.receive_message()
        if callable(self.trace):
            self.trace('-->', context, message)

        # assuming protocol is thread-safe and dispatcher is thread-safe, as
        # long as its immutable

        def handle_message(context: Any, message: bytes) -> None:
            """Parse, process and reply a single request."""
            try:
                request = self.protocol.parse_request(message)
                #print(f"received {request.unique_id}")
            except tinyrpc.exc.RPCError as e:
                response = e.error_respond()
            else:
                if callable(self.authenticator):
                    try:
                        self.authenticator(context, request)
                    except Exception as e:
                        response = request.error_respond(e)
                    else:
                        response = self.dispatcher.dispatch(
                            request, getattr(self.protocol, '_caller', None)
                        )
                else:
                    response = self.dispatcher.dispatch(
                        request, getattr(self.protocol, '_caller', None)
                    )

            # send reply
            if response is not None:
                result = response.serialize()
                #print(f"reply {response.unique_id}")
                if callable(self.trace):
                    self.trace('<--', context, result)
                self.transport.send_reply(context, result)

        def guarded(context: Any, message: bytes) -> None:
            """Run the handler, and answer even if it fails.

            Serializing a response can raise -- a result the protocol cannot
            encode is the usual way -- and so can a protocol that reports a
            malformed request with something other than an RPCError.  Without
            this, such a failure sent no reply and logged nothing, so the
            caller waited out its timeout with no idea why.
            """
            request = None
            try:
                request = self.protocol.parse_request(message)
            except Exception:
                pass                    # handle_message reports this properly

            try:
                handle_message(context, message)
            except Exception as e:
                self._report_failure(context, request, e)

        self._spawn(guarded, context, message)

    def _report_failure(self, context: Any, request: Any,
                        error: Exception) -> None:
        """Log a handler that failed, and tell the caller if we still can."""
        log = self.logger if self.logger is not None else logger
        log.exception('error handling a request: %s', error)

        if request is None:
            return
        try:
            response = request.error_respond(error)
            if response is not None:
                self.transport.send_reply(context, response.serialize())
        except Exception:
            log.exception('could not report that failure to the caller')

    def _spawn(self, func: Callable, *args: Any, **kwargs: Any) -> None:
        """Spawn a handler function.

        This function is overridden in subclasses to provide concurrency.

        In the base implementation, it simply calls the supplied function
        ``func`` with ``*args`` and ``**kwargs``. This results in a
        single-threaded, single-process, synchronous server.

        :param func: A callable to call.
        :param args: Arguments to ``func``.
        :param kwargs: Keyword arguments to ``func``.
        """
        func(*args, **kwargs)


class AsyncioRPCServer(RPCServer):
    """An :py:mod:`asyncio` server.

    Note what the dispatcher does and does not do for you here.  An ordinary
    synchronous method is called directly, on the event loop's thread, so one
    that blocks stalls every other call in flight -- pass an ``executor`` to
    have those run off the loop instead.  A method defined with ``async def``
    is awaited, which the synchronous dispatcher cannot do on its own.

    :param executor: Optional :py:class:`concurrent.futures.Executor` to run
        synchronous methods on.  Without it they run on the event loop.
    """

    def __init__(
            self, transport: ServerTransport, protocol: RPCProtocol,
            dispatcher: RPCDispatcher, executor: Any = None
    ) -> None:
        super().__init__(transport, protocol, dispatcher)

        self.executor = executor
        self.tasks = set()
        self.ev_quit = asyncio.Event()

    async def stop(self) -> None:
        """Ask the serve loop to finish, and stop the transport."""
        self.ev_quit.set()
        stop = getattr(self.transport, 'stop', None)
        if stop is not None:
            result = stop()
            if asyncio.iscoroutine(result):
                await result
        for task in list(self.tasks):
            task.cancel()

    async def serve_forever(self) -> None:
        """Handle requests until :py:meth:`stop` is awaited."""
        task = asyncio.create_task(self.transport.start())
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        try:
            while not self.ev_quit.is_set():
                try:
                    await self.receive_one_message()
                except TransportTimeout:
                    # No request arrived within the transport's poll
                    # interval, which is how it gives us the chance to
                    # re-test ev_quit.
                    continue
        finally:
            task.cancel()

    async def receive_one_message(self) -> None:
        """Handle a single request.

        Polls the transport for a new message.

        After a new message has arrived :py:meth:`_spawn` is called with a handler
        function and arguments to handle the request.

        The handler function will try to decode the message using the supplied
        protocol, if that fails, an error response will be sent. After decoding
        the message, the dispatcher will be asked to handle the resulting
        request and the return value (either an error or a result) will be sent
        back to the client using the transport.
        """
        context, message = await self.transport.receive_message()
        if callable(self.trace):
            self.trace('-->', context, message)

        # assuming protocol is thread-safe and dispatcher is thread-safe, as
        # long as its immutable

        async def handle_message(context: Any, message: bytes) -> None:
            """Parse, process and reply a single request."""
            try:
                request = self.protocol.parse_request(message)
                #print(f"received {request.unique_id}")
            except tinyrpc.exc.RPCError as e:
                response = e.error_respond()
            else:
                response = await self._dispatch(request)

            # send reply
            if response is not None:
                result = response.serialize()
                #print(f"reply {response.unique_id}")
                if callable(self.trace):
                    self.trace('<--', context, result)
                await self.transport.send_reply(context, result)

        async def guarded(context: Any, message: bytes) -> None:
            """As for the synchronous server: answer even if the handler
            fails, rather than leaving the caller to time out."""
            request = None
            try:
                request = self.protocol.parse_request(message)
            except Exception:
                pass

            try:
                await handle_message(context, message)
            except Exception as e:
                await self._report_failure_async(context, request, e)

        self._spawn(guarded, context, message)

    async def _report_failure_async(self, context: Any, request: Any,
                                    error: Exception) -> None:
        log = self.logger if self.logger is not None else logger
        log.exception('error handling a request: %s', error)

        if request is None:
            return
        try:
            response = request.error_respond(error)
            if response is not None:
                await self.transport.send_reply(context, response.serialize())
        except Exception:
            log.exception('could not report that failure to the caller')

    async def _dispatch(self, request: Any) -> Any:
        """Dispatch a request, awaiting the method if it is a coroutine.

        RPCDispatcher is synchronous: it calls the method and takes whatever
        comes back as the result, so given an ``async def`` method it would
        hand back the coroutine object, which then fails to serialize.  A
        whole async dispatcher is not needed to fix that -- the coroutine is
        simply awaited here, and the exception it may raise is turned into an
        error response the same way a synchronous one would be.

        A synchronous method runs on the event loop unless an executor was
        given, in which case it runs there so that a blocking method does not
        stall every other call in flight.
        """
        caller = getattr(self.protocol, '_caller', None)

        if self.executor is not None and not _is_coroutine_method(
                self.dispatcher, request):
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                self.executor, self.dispatcher.dispatch, request, caller)

        response = self.dispatcher.dispatch(request, caller)

        result = getattr(response, 'result', None)
        if asyncio.iscoroutine(result):
            try:
                response.result = await result
            except Exception as e:
                return request.error_respond(e)
        return response

    def _spawn(self, func: Callable, *args: Any, **kwargs: Any) -> None:
        """Spawn a handler function.

        This function is overridden in subclasses to provide concurrency.

        In the base implementation, it simply calls the supplied function
        ``func`` with ``*args`` and ``**kwargs``. This results in a
        single-threaded, single-process, synchronous server.

        :param func: A callable to call.
        :param args: Arguments to ``func``.
        :param kwargs: Keyword arguments to ``func``.
        """
        # TODO: how to limit to N tasks?
        task = asyncio.create_task(func(*args, **kwargs))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        task.add_done_callback(self._log_task_result)

    def _log_task_result(self, task: Any) -> None:
        """Read a finished task's exception, so it is reported rather than
        surfacing much later as "Task exception was never retrieved"."""
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            log = self.logger if self.logger is not None else logger
            log.error('handler task failed', exc_info=error)
