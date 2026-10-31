from ucall import posix as ucall
from ucall._server import _Server


class Server(_Server):
    def __init__(self, **kwargs):
        self.server = ucall.Server(**kwargs)
