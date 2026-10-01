#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""A client that keeps several calls in flight over one transport.

:py:class:`~tinyrpc.client.RPCClient` couples sending a request to receiving
its reply, so a caller blocks for a full round trip and only one call can be
outstanding at a time.  :py:class:`MultiplexingRPCClient` separates the two:
:py:meth:`~MultiplexingRPCClient.begin_call` sends a request and hands back a
:py:class:`PendingCall`, and the caller collects the result whenever it suits
them.  Replies arriving on the shared transport are demultiplexed onto the
right pending call by a background loop
(:py:meth:`~MultiplexingRPCClient.receive_forever`).

This is *threading*, not :py:mod:`asyncio`.  Nothing here is a coroutine and
nothing is awaited; the concurrency comes from running
:py:meth:`~MultiplexingRPCClient.receive_forever` in a thread of its own.  The
asyncio machinery lives in :py:class:`~tinyrpc.server.AsyncioRPCServer` and
the ``Asyncio*`` transports, and the two are unrelated.

.. important::

    Demultiplexing works by matching the reply's correlation id against the
    request's, so **the protocol must put an id on the reply**.  JSON-RPC and
    msgpack-RPC do.  **XML-RPC does not** -- it has no id field at all and
    correlates a reply with its request by connection and ordering -- so
    XML-RPC cannot be used here, and :py:class:`MultiplexingRPCClient`
    rejects such a protocol when it is constructed rather than failing
    obscurely on the first reply.
"""

import logging
import threading
import time
from typing import Any, Dict, List, Optional

from . import RPCClient
from .exc import RPCError
from .protocols import RPCErrorResponse, RPCProtocol, RPCRequest, RPCResponse
from .transports import ClientTransport

logger = logging.getLogger(__name__)


class PendingCall:
    """A handle on a call that has been sent but not yet answered.

    Returned by :py:meth:`MultiplexingRPCClient.begin_call`; pass it to
    :py:meth:`MultiplexingRPCClient.receive_reply` to collect the result.

    .. py:attribute:: msg_id

        The request's correlation id, which is the key the reply is matched
        on.

    .. py:attribute:: response

        The :py:class:`~tinyrpc.protocols.RPCResponse` once one has arrived,
        otherwise ``None``.
    """

    __slots__ = ('msg_id', 'cond', 'response')

    def __init__(self, msg_id: Any) -> None:
        self.msg_id = msg_id
        self.cond = threading.Condition()
        self.response = None

    def done(self) -> bool:
        """Whether a reply has arrived."""
        with self.cond:
            return self.response is not None

    def __repr__(self) -> str:
        return '<PendingCall %r %s>' % (
            self.msg_id, 'done' if self.done() else 'waiting')


class MultiplexingRPCClient(RPCClient):
    """Client that keeps several calls in flight over a single transport.

    :param protocol: An :py:class:`~tinyrpc.RPCProtocol` instance.  It must
        carry a correlation id on replies; see the note in the module
        docstring.
    :param transport: A
        :py:class:`~tinyrpc.transports.NonBlockingClientTransport`, i.e. one
        providing ``send_message_noblock`` and ``receive_reply``.
    :raises TypeError: when the transport cannot send without blocking.
    """

    def __init__(
            self, protocol: RPCProtocol, transport: ClientTransport,
            logger_: Any = None
    ) -> None:
        super().__init__(protocol, transport)

        if not getattr(protocol, 'supports_reply_correlation', True):
            raise TypeError(
                "%s cannot be used with %s: its replies carry no correlation "
                "id, so a reply cannot be matched to the request it answers "
                "and only one call can be outstanding per connection. Use "
                "RPCClient instead, or a protocol that carries an id such as "
                "JSONRPCProtocol or MSGPACKRPCProtocol."
                % (type(self).__name__, type(protocol).__name__))

        for required in ('send_message_noblock', 'receive_reply'):
            if not callable(getattr(transport, required, None)):
                raise TypeError(
                    "%s requires a NonBlockingClientTransport; %s has no "
                    "%s()" % (type(self).__name__,
                              type(transport).__name__, required))

        self.logger = logger_ if logger_ is not None else logger
        self.lock = threading.RLock()
        self.tracking_board = {}
        self.trace = False
        self.ev_quit = threading.Event()

    # ------------------------------------------------------ receive loop --

    def process_events(self) -> None:
        self.process_incoming()
        if self.trace:
            with self.lock:
                self.logger.debug("tracking %s", list(self.tracking_board))

    #: How long the loop waits for a reply before looking up to re-test
    #: ev_quit.  A reply does not wait for this: the transport's queue hands
    #: one over the moment it arrives, so a longer wait adds no latency and
    #: saves the wakeups.  At 0.0001 the loop woke ten thousand times a
    #: second to find nothing, which measured 4% of a core per idle client.
    _process_timeout = 0.25

    #: How long to pause after finding no connection at all.  receive_reply()
    #: raises ConnectionError immediately in that case rather than waiting,
    #: so without a pause the loop span: a client whose connection had
    #: dropped burned a whole core until something dialled again -- and if
    #: nothing did, indefinitely.
    _disconnected_pause = 0.1

    def process_incoming(self) -> None:
        """Take one reply off the transport and hand it to its pending call.

        This runs on the demultiplexing thread, so it must not raise: a single
        unmatched or malformed reply must not be able to take the loop down
        and leave the client permanently deaf.  Anything unexpected is logged
        and dropped.
        """
        try:
            reply = self.transport.receive_reply(
                timeout=self._process_timeout)
        except TimeoutError:
            # Nothing waiting.  Note that tinyrpc.exc.TimeoutError derives
            # from the builtin, so this catches whichever the transport uses.
            return
        except ConnectionError:
            # The connection went away.  Ordinary for a transport that dials
            # again on the next send, and not worth a traceback every time
            # round a loop that polls -- the calls that were in flight
            # surface as timeouts, which is where the decision to retry
            # belongs.  The pause is what keeps this from becoming a spin,
            # since there is no socket to wait on.
            self.ev_quit.wait(timeout=self._disconnected_pause)
            return
        except Exception:
            self.logger.exception("error reading from transport")
            return

        if reply is None:
            return

        try:
            response = self.protocol.parse_reply(reply)
        except Exception:
            self.logger.exception("could not parse a reply; dropping it")
            return

        try:
            self._track_board_add_msg(response)
        except Exception:
            self.logger.exception("error dispatching a reply; dropping it")

    def receive_forever(self, ev_quit: threading.Event = None) -> None:
        """Demultiplex replies until asked to stop.

        Run this in a thread of its own; nothing else drives the transport.
        """
        if ev_quit is not None:
            self.ev_quit = ev_quit

        while not self.ev_quit.is_set():
            self.process_events()

    def stop(self) -> None:
        self.ev_quit.set()

    # ------------------------------------------------------------ calling --

    def send_message(
            self,
            req: RPCRequest,
            one_way: bool = False,
            transport: ClientTransport = None,
    ) -> Optional[PendingCall]:
        """Send a request without waiting for its reply.

        :return: A :py:class:`PendingCall` to collect the reply with, or
            ``None`` for a one-way request, which will not be answered.
        """
        tport = self.transport if transport is None else transport

        msg_id = req.unique_id
        msg = req.serialize()

        # Register before sending, so that a reply cannot arrive before there
        # is anywhere to put it.
        ctx = None
        if msg_id is not None and not one_way:
            ctx = self._track_board_set_msg(msg_id)

        try:
            tport.send_message_noblock(msg)
        except Exception:
            # Nothing is going to answer a request that was never sent.
            if ctx is not None:
                self._track_board_del_msg(msg_id)
            raise

        return ctx

    def receive_reply(
            self,
            ctx: PendingCall,
            no_exception: bool = False,
            timeout: Any = None
    ) -> Optional[RPCResponse]:
        """Wait for the reply to a pending call and return it.

        :param ctx: The :py:class:`PendingCall` from :py:meth:`begin_call`.
        :param no_exception: Return an error response rather than raising it.
        :param timeout: Seconds to wait, or ``None`` to wait indefinitely.
        :raises TimeoutError: when no reply arrived within ``timeout``.
        """
        try:
            with ctx.cond:
                if timeout is None:
                    while ctx.response is None:
                        ctx.cond.wait()
                else:
                    deadline = time.monotonic() + timeout
                    while ctx.response is None:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError(
                                "timed out waiting for a reply to %r"
                                % (ctx.msg_id,))
                        # A wait may return early without a response; the
                        # loop condition is what decides, not the wakeup.
                        ctx.cond.wait(timeout=remaining)

                response = ctx.response
        finally:
            # Whatever happened, stop tracking this call.  Leaving a timed-out
            # id on the board would leak it, and would also make a later
            # request carrying the same id look like a duplicate.
            self._track_board_del_msg(ctx.msg_id)

            # The protocol keeps its own record of ids it expects replies
            # for, and only a reply clears it.  We are the only one who knows
            # this call is over, so say so; otherwise a call that timed out
            # leaks one layer further down than the board.
            forget = getattr(self.protocol, 'forget_request', None)
            if callable(forget):
                forget(ctx.msg_id)

        if not no_exception and isinstance(response, RPCErrorResponse):
            if hasattr(self.protocol, 'raise_error') and callable(
                    self.protocol.raise_error):
                response = self.protocol.raise_error(response)
            else:
                raise RPCError(
                    'Error calling remote procedure: %s' % response.error
                )

        return response

    def _send_and_handle_reply(
            self,
            req: RPCRequest,
            one_way: bool = False,
            transport: ClientTransport = None,
            no_exception: bool = False,
            timeout: Any = None
    ) -> Optional[RPCResponse]:
        # Signature deliberately matches RPCClient._send_and_handle_reply,
        # including ``transport``: the inherited call_all() passes its
        # arguments positionally.
        ctx = self.send_message(req, one_way=one_way, transport=transport)

        if ctx is None:
            return

        return self.receive_reply(ctx, no_exception=no_exception,
                                  timeout=timeout)

    def call(
            self, method: str, args: List, kwargs: Dict,
            one_way: bool = False, timeout: Any = None
    ) -> Any:
        """Call a method and wait for its result.

        Blocking, like :py:meth:`RPCClient.call`; the difference is that other
        calls may be in flight on the same transport at the same time.

        :param timeout: Seconds to wait for the reply, or ``None`` to wait
            indefinitely.
        """
        req = self.protocol.create_request(method, args, kwargs, one_way)

        rep = self._send_and_handle_reply(req, one_way=one_way,
                                          timeout=timeout)

        if one_way:
            return

        return rep.result

    def begin_call(
            self, method: str, args: List, kwargs: Dict, one_way: bool = False
    ) -> Optional[PendingCall]:
        """Send a call and return at once, without waiting for the result.

        Pass the returned :py:class:`PendingCall` to :py:meth:`receive_reply`
        to collect the result.  Returns ``None`` for a one-way request.
        """
        req = self.protocol.create_request(method, args, kwargs, one_way)

        ctx = self.send_message(req, one_way=one_way)

        if one_way:
            return

        return ctx

    # ------------------------------------------------------ tracking board --

    def _track_board_set_msg(self, msg_id: Any) -> PendingCall:
        with self.lock:
            if msg_id in self.tracking_board:
                raise ValueError("duplicate msg_id '%s'" % (msg_id,))
            ctx = PendingCall(msg_id)
            self.tracking_board[msg_id] = ctx
            return ctx

    def _track_board_add_msg(self, response: RPCResponse) -> bool:
        """Hand a reply to the call that is waiting for it.

        :return: ``True`` if it was matched, ``False`` if no call was waiting
            for that id -- a late reply to a call that already timed out, a
            duplicate, or a reply to something we never sent.  That is not
            worth an exception on the demultiplexing thread, so it is
            reported by the return value and logged by the caller.
        """
        msg_id = getattr(response, 'unique_id', None)

        with self.lock:
            ctx = self.tracking_board.get(msg_id)
            if ctx is None:
                self.logger.warning(
                    "discarding a reply with no matching request (id=%r); "
                    "it may have arrived after the call timed out, or the "
                    "protocol may not carry a correlation id", msg_id)
                return False

            with ctx.cond:
                ctx.response = response
                ctx.cond.notify_all()
            return True

    def _track_board_del_msg(self, msg_id: Any) -> None:
        with self.lock:
            self.tracking_board.pop(msg_id, None)


#: Kept so that ``AsyncRPCClient`` still resolves for anything that has not
#: been updated yet.  The name was misleading: this client has nothing to do
#: with :py:mod:`asyncio`.
#: TODO: remove once nothing refers to it.
AsyncRPCClient = MultiplexingRPCClient
