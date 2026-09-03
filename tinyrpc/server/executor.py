# -*- coding: utf-8 -*-
"""Server definition.

Defines and implements a concurrent asynchronous server using a
concurrent.futures.Executor.
"""
from typing import Callable
#from concurrent.futures import Executor
import threading

from . import RPCServer
from ..transports import TransportTimeout


class RPCServerExecutor(RPCServer):
    """Asynchronous RPCServer.

    This implementation of :py:class:`~tinyrpc.server.RPCServer` uses
    a concurrent.futures.Executor to spawn new client handlers, resulting
    in asynchronous handling of clients using threads or processes.
    """
    def __init__(self, transport, protocol, dispatcher,
                 executor, ev_quit=None):
        super().__init__(transport, protocol, dispatcher)

        self.executor = executor

        if ev_quit is None:
            ev_quit = threading.Event()
        self.ev_quit = ev_quit

    def _spawn(self, func: Callable, *args, **kwargs):
        self.executor.submit(func, *args, **kwargs)

    def start(self):
        """Start the transport, if it needs starting, then the serve loop."""
        start = getattr(self.transport, 'start', None)
        if callable(start):
            start()
        self.executor.submit(self.serve_forever)

    def serve_forever(self):
        while not self.ev_quit.is_set():
            try:
                self.receive_one_message()
            except TransportTimeout:
                # No request arrived within the transport's poll interval.
                # That is how a polling transport gives us this chance to
                # re-test ev_quit, so just go round again.
                continue

    def stop(self):
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
