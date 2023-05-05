# -*- coding: utf-8 -*-
"""Server definition.

Defines and implements a concurrent asynchronous server using a
concurrent.futures.Executor.
"""
from typing import Callable
#from concurrent.futures import Executor
import threading

from . import RPCServer


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
        self.executor.submit(self.serve_forever)

    def serve_forever(self):
        while not self.ev_quit.is_set():
            self.receive_one_message()

    def stop(self):
        self.ev_quit.set()
