"""HTTP servers and clients with typed handlers, request batching and Noise, polled by threads the application owns.

File: python/ucall/__init__.py
Author: Ash Vardanian
Date: March 13, 2023
"""

from ucall.lib import *
from ucall.lib import __version__


async def _until_final(pending, finish):
    """Awaits an outcome the library has no wake-up for, polling `pending()` between other tasks.

    The first pause only yields to the running loop, and each later one sleeps twice as long, from
    1 µs up to 1 ms, so no thread ever waits on the library; `finish()` then reads the final outcome,
    which returns at once.
    """
    import asyncio

    backoff = 0.0
    while pending():
        await asyncio.sleep(backoff)
        backoff = min(max(backoff * 2, 1e-6), 1e-3)
    return finish()
