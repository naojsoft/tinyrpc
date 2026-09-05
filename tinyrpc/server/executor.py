# -*- coding: utf-8 -*-
"""Server definition.

Defines and implements a concurrent asynchronous server using a
concurrent.futures.Executor.
"""
from concurrent.futures import Executor
from typing import Any, Callable, Optional
import threading

from . import RPCServer, logger as _server_logger
from ..dispatch import RPCDispatcher
from ..protocols import RPCProtocol
from ..transports import ServerTransport, TransportTimeout


class RPCServerExecutor(RPCServer):
    """Asynchronous RPCServer.

    This implementation of :py:class:`~tinyrpc.server.RPCServer` uses
    a concurrent.futures.Executor to spawn new client handlers, resulting
    in asynchronous handling of clients using threads or processes.
    """
    def __init__(self, transport: ServerTransport, protocol: RPCProtocol,
                 dispatcher: RPCDispatcher, executor: Executor,
                 ev_quit: Optional[threading.Event] = None) -> None:
        super().__init__(transport, protocol, dispatcher)

        self.executor = executor

        if ev_quit is None:
            ev_quit = threading.Event()
        self.ev_quit = ev_quit

    def _spawn(self, func: Callable, *args: Any, **kwargs: Any) -> None:
        future = self.executor.submit(func, *args, **kwargs)
        future.add_done_callback(self._log_future_result)

    def _log_future_result(self, future: Any) -> None:
        """Read a finished handler's exception, so it is reported.

        An Executor stores an exception on its Future and says nothing.  With
        the Future discarded, as it was, a handler that failed left no reply
        and no trace of why.
        """
        if future.cancelled():
            return
        try:
            error = future.exception()
        except Exception:
            return
        if error is not None:
            log = self.logger if self.logger is not None else _server_logger
            log.error('handler failed', exc_info=error)

    def start(self) -> None:
        """Start the transport, if it needs starting, then the serve loop."""
        start = getattr(self.transport, 'start', None)
        if callable(start):
            start()
        self.executor.submit(self.serve_forever)

    def serve_forever(self) -> None:
        while not self.ev_quit.is_set():
            try:
                self.receive_one_message()
            except TransportTimeout:
                # No request arrived within the transport's poll interval.
                # That is how a polling transport gives us this chance to
                # re-test ev_quit, so just go round again.
                continue

    def stop(self) -> None:
        """Ask the serve loop to exit, and shut the transport down.

        Setting ``ev_quit`` alone only ends the loop once ``receive_one_message``
        returns.  Transports that poll raise :py:exc:`TransportTimeout` and so
        notice promptly; ones that block indefinitely will not exit until the
        next request arrives.
        """
        self.ev_quit.set()
        stop = getattr(self.transport, 'stop', None)
        if callable(stop):
            stop()
