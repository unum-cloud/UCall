import inspect
from typing import Callable, get_type_hints
from functools import wraps
from io import BytesIO

import numpy as np
from PIL import Image


class _Server:

    def __init__(self) -> None:
        self.server = None

    def __call__(self, func: Callable):
        return self.route(func)

    def run(self, max_cycles: int = -1, max_seconds: float = -1):
        return self.server.run(max_cycles, max_seconds)

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
                res.format = "tiff"
            res.save(buf, res.format, compression="raw", compression_level=0)

            return buf.getvalue()

        return res

    def route(self, func: Callable):
        hints = get_type_hints(func)

        @wraps(func)
        def wrapper(*args, **kwargs):
            new_args = []
            new_kwargs = {}

            for arg, hint in zip(args, hints.values()):
                assert isinstance(hint, type), "Hint must be a type!"
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
        self.server.route(wrapper)
        return wrapper
