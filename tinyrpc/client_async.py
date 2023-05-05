import time
import threading
from typing import List, Any, Dict, Callable, Optional
from types import SimpleNamespace

from . import RPCClient
from .transports import ClientTransport
from .protocols import (RPCErrorResponse, RPCProtocol, RPCRequest,
                        RPCResponse, RPCBatchResponse)


class AsyncRPCClient(RPCClient):
    """Client for making RPC calls to connected servers.

    :param protocol: An :py:class:`~tinyrpc.RPCProtocol` instance.
    :type protocol: RPCProtocol
    :param transport: The data transport mechanism
    :type transport: ClientTransport
    """
    def __init__(
            self, protocol: RPCProtocol, transport: ClientTransport
    ) -> None:
        super().__init__(protocol, transport)

        self.lock = threading.RLock()
        self.tracking_board = dict()
        self.trace = False
        self._process_timeout = 0.0001

    def process_events(self):
        #self.transport.process_events()
        self.process_incoming()
        if self.trace:
            with self.lock:
                print(f"track events", list(self.tracking_board.keys()))

    def process_incoming(self):
        try:
            reply = self.transport.receive_reply(timeout=self._process_timeout)
        except TimeoutError:
            return

        if reply is not None:
            response = self.protocol.parse_reply(reply)

            self._track_board_add_msg(response)

    def receive_forever(self, ev_quit=None):
        if ev_quit is None:
            ev_quit = threading.Event()
        self.ev_quit = ev_quit

        while not self.ev_quit.is_set():
            self.process_events()

    def stop(self):
        self.ev_quit.set()

    def send_message(
            self,
            req: RPCRequest,
            one_way: bool = False,
            transport: ClientTransport = None,
    ) -> Any:
        tport = self.transport if transport is None else transport

        msg_id = req.unique_id
        msg = req.serialize()

        if msg_id is not None and not one_way:
            ctx = self._track_board_set_msg(msg_id)
        else:
            ctx = None

        if hasattr(tport, 'send_message_noblock'):
            tport.send_message_noblock(msg)

        return ctx

    def receive_reply(
            self,
            ctx: SimpleNamespace,
            no_exception: bool = False,
            timeout: Any = None
    ) -> Optional[RPCResponse]:

        # start_time = time.time()
        with ctx.cond:
            # while ctx.response is None:
            #     ok = ctx.cond.wait(timeout=self._process_timeout)
            #     if ok:
            #         if ctx.response is None:
            #             raise ValueError("awakened with no response")
            #         break
            #     if timeout is not None and time.time() - start_time > timeout:
            #         raise TimeoutError("timed out waiting for reply")

            #     self.process_incoming()
            if ctx.response is None:
                ok = ctx.cond.wait(timeout=timeout)
                if not ok:
                    raise TimeoutError("timed out waiting for reply")
                if ctx.response is None:
                    raise ValueError("awakened with no response")

        # <-- got a response to our message
        response = ctx.response
        # stop tracking it
        self._track_board_del_msg(response.unique_id)

        # process response if it is an error
        if not no_exception and isinstance(response, RPCErrorResponse):
            if hasattr(self.protocol, 'raise_error') and callable(
                    self.protocol.raise_error):
                response = self.protocol.raise_error(response)
            else:
                raise RPCError(
                    'Error calling remote procedure: %s' % response.error
                )

        return response

    def _track_board_set_msg(self, msg_id):
        if self.trace:
            print(f"send {msg_id}")
        with self.lock:
            # check to see that msg_id does not exist in track board
            # it shouldn't, unless something has been restarted
            if msg_id in self.tracking_board:
                raise ValueError(f"duplicate msg_id '{msg_id}'")
            cnd = threading.Condition()
            ctx = SimpleNamespace(cond=cnd, response=None)
            self.tracking_board[msg_id] = ctx
            if self.trace:
                print(f"track send", list(self.tracking_board.keys()))
            return ctx

    def _track_board_add_msg(self, response):
        msg_id = response.unique_id
        if self.trace:
            print(f"reply to {msg_id}")
        with self.lock:
            if msg_id in self.tracking_board:
                ctx = self.tracking_board[msg_id]
                with ctx.cond:
                    ctx.response = response
                    ctx.cond.notify_all()
            else:
                # <-- received a reply before we sent it!
                raise ValueError(f"msg_id '{msg_id}' unknown")
                # cnd = threading.Condition()
                # ctx = SimpleNamespace(cond=cnd, response=response)
                # self.tracking_board[msg_id] = ctx
            if self.trace:
                print(f"track reply", list(self.tracking_board.keys()))

    def _track_board_del_msg(self, msg_id):
        with self.lock:
            del self.tracking_board[msg_id]
            if self.trace:
                print(f"track del", list(self.tracking_board.keys()))

    def _send_and_handle_reply(
            self,
            req: RPCRequest,
            one_way: bool = False,
            no_exception: bool = False,
            timeout: Any = None
    ) -> Optional[RPCResponse]:

        # sends ...
        ctx = self.send_message(req, one_way=one_way)

        if ctx is None:
            # ... and be done
            return

        return self.receive_reply(ctx, no_exception=no_exception,
                                  timeout=timeout)

    def call(
            self, method: str, args: List, kwargs: Dict, one_way: bool = False
    ) -> Any:
        req = self.protocol.create_request(method, args, kwargs, one_way)

        rep = self._send_and_handle_reply(req, one_way)

        if one_way:
            return

        return rep.result

    def call_async(
            self, method: str, args: List, kwargs: Dict, one_way: bool = False
    ) -> Any:
        """Call a remote method asynchronously.

        Similar to call(), but returns a context.  Call receive_reply(context)
        to receive the reply.
        """
        req = self.protocol.create_request(method, args, kwargs, one_way)

        ctx = self.send_message(req, one_way=one_way)

        if one_way:
            return

        return ctx
