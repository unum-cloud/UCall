import platform
import inspect
from typing import Callable, Union, get_type_hints
from functools import wraps
from io import BytesIO

import numpy as np
from PIL import Image


def supports_io_uring() -> bool:
    if platform.system() != 'Linux':
        return False
    major, minor, _ = platform.release().split('.', 3)
    major = int(major)
    minor = int(minor)
    if major > 5 or (major == 5 and minor >= 19):
        return True
    return False


def only_native_types(hints: dict[str, type]) -> bool:
    for hint in hints.values():
        if not isinstance(hint, Union[bool, int, float, str]):
            return False
    return True


class Protocol():
    TCP = 0
    HTTP = 1
    JSONRPC_TCP = 2
    JSONRPC_HTTP = 3
    REST = 4


class Server:

    def __init__(self, uring_if_possible=True, epoll_if_possible=False, **kwargs) -> None:
        if uring_if_possible and supports_io_uring():
            from ucall import uring as backend
        elif epoll_if_possible and platform.system() == 'Linux':
            from ucall import epoll as backend
        else:
            from ucall import posix as backend

        self.native = backend.Server(**kwargs)

    def __call__(self, func: Callable):
        return self.route(func)

    def run(self, max_cycles: int = -1, max_seconds: float = -1):
        return self.native.run(max_cycles, max_seconds)

    def unpack(self, arg: bytes, hint: type):
        if hint == bytes or hint == bytearray:
            return arg

        bin = BytesIO(arg)

        if hint == np.ndarray:
            return np.load(bin, allow_pickle=True)
        if hint == Image.Image:
            return Image.open(bin)

    def pack(self, res):
        if isinstance(res, np.ndarray):
            buf = BytesIO()
            np.save(buf, res)
            return buf.getvalue()

        if isinstance(res, Image.Image):
            buf = BytesIO()
            if not res.format:
                res.format = 'tiff'
            res.save(buf, res.format, compression='raw', compression_level=0)

            return buf.getvalue()

        return res

    def route(self, func: Callable):
        hints = get_type_hints(func)
        for name, hint in hints.items():
            assert isinstance(hint, type), f'Hint for {name} must be a type!'

        # Let's optimize, avoiding the need for the second layer of decorators:
        if only_native_types(hints):
            self.native.route(func)
            return func

        @wraps(func)
        def wrapper(*args, **kwargs):
            new_args = []
            new_kwargs = {}

            for arg, hint in zip(args, hints.values()):
                if isinstance(arg, bytes):
                    new_args.append(self.unpack(arg, hint))
                else:
                    new_args.append(arg)

            for kw, arg in kwargs.items():
                if isinstance(arg, bytes):
                    new_kwargs[kw] = self.unpack(arg, hints[kw])
                else:
                    new_kwargs[kw] = arg

            res = func(*new_args, **new_kwargs)
            return self.pack(res)

        wrapper.__signature__ = inspect.signature(func)
        self.native.route(wrapper)
        return wrapper
