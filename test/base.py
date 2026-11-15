"""Settings, matrices and fixtures the Python suites share: the seed and filter the environment
names, the backends a server runs on, loopback interfaces, and polling threads.

Loaded as a plugin from `conftest`, which keeps only pytest's hooks.

File: test/base.py
Author: Ash Vardanian
Date: October 19, 2026
"""

import contextlib
import os
import pathlib
import random
import re
import secrets
import shutil
import sys
import tempfile
import threading
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass

import pytest

import ucall


@dataclass(frozen=True)
class Settings:
    """Every `UCALL_*` variable the Python suites read, parsed once at import."""

    seed: int
    filter: re.Pattern[str] | str
    """`UCALL_FILTER` compiled, or its text when it is no valid regex."""

    def selects(self, name: str) -> bool:
        """Whether `name` passes the filter: every name for an empty one, else a regex search or a substring."""
        if not self.filter:
            return True
        if isinstance(self.filter, re.Pattern):
            return self.filter.search(name) is not None
        return self.filter in name


def read_settings() -> Settings:
    """Reads `UCALL_SEED`, an unsigned integer or `random`, and `UCALL_FILTER`; exits on a seed that does not parse."""
    seed_text = os.environ.get("UCALL_SEED") or "42"
    if seed_text == "random":
        seed = secrets.randbits(32)
    elif seed_text.isascii() and seed_text.isdigit():
        seed = int(seed_text)
    else:
        raise SystemExit(f'UCALL_SEED="{seed_text}" does not parse, expected an unsigned integer or random')
    pattern = os.environ.get("UCALL_FILTER") or ""
    try:
        compiled: re.Pattern[str] | str = re.compile(pattern) if pattern else ""
    except re.error:
        compiled = pattern
    return Settings(seed=seed, filter=compiled)


SETTINGS = read_settings()

BACKENDS = {
    ucall.Backend.POSIX: sys.platform.startswith(("linux", "darwin", "freebsd")),
    ucall.Backend.LINUX_EPOLLAIO: sys.platform.startswith("linux"),
    ucall.Backend.LINUX_URING612: sys.platform.startswith("linux"),
    ucall.Backend.LINUX_URING618: sys.platform.startswith("linux"),
    ucall.Backend.BSD_KQUEUE: sys.platform.startswith(("darwin", "freebsd")),
    ucall.Backend.WINDOWS_IOCP: sys.platform == "win32",
    ucall.Backend.WINDOWS_RIO: sys.platform == "win32",
}
"""Every backend, and whether this platform has its kernel facility."""


@pytest.fixture
def seed(request: pytest.FixtureRequest) -> int:
    """A per-test seed from `UCALL_SEED` and the test's node id, so a filtered run reproduces an unfiltered one."""
    return SETTINGS.seed ^ zlib.crc32(request.node.nodeid.encode())


@pytest.fixture
def rng(seed: int) -> random.Random:
    """A generator private to this test, so a neighbour's draws cannot shift this one's."""
    return random.Random(seed)


@pytest.fixture(params=list(BACKENDS))
def backend(request: pytest.FixtureRequest) -> ucall.Backend:
    """Runs a server test on each backend, skipping those whose kernel facility this platform lacks."""
    if not BACKENDS[request.param]:
        pytest.skip(f"{request.param.name.lower()} needs a kernel facility {sys.platform} lacks")
    return request.param


@pytest.fixture
def loopback() -> Callable[..., ucall.Interface]:
    """Makes interfaces on a free loopback port, eight connections unless the case asks otherwise."""

    def interface(**options: object) -> ucall.Interface:
        return ucall.Interface("127.0.0.1:0", **{"connections": 8, **options})

    return interface


@pytest.fixture
def serving() -> Callable[[ucall.Server], contextlib.AbstractContextManager[str]]:
    """Polls every event loop and drains every batch endpoint on threads of the test's own, yielding the base URL."""

    @contextlib.contextmanager
    def serve(server: ucall.Server) -> Iterator[str]:
        threads = [threading.Thread(target=server.take_calls, args=(loop,)) for loop in range(server.event_loops)]
        threads += [threading.Thread(target=endpoint.take_batches) for endpoint in server.batch_endpoints]
        for thread in threads:
            thread.start()
        try:
            yield f"http://{server.addresses[0]}"
        finally:
            server.stop()
            for thread in threads:
                thread.join()

    return serve


@pytest.fixture
def direct_directory(tmp_path: pathlib.Path) -> Iterator[pathlib.Path]:
    """A directory whose files open with `os.O_DIRECT`, under `UCALL_TEST_DIRECT_DIRECTORY` when set, else `tmp_path`."""
    base = os.environ.get("UCALL_TEST_DIRECT_DIRECTORY")
    directory = pathlib.Path(tempfile.mkdtemp(prefix="ucall-direct-", dir=base)) if base else tmp_path
    probe = directory / "probe.bin"
    probe.write_bytes(bytes(1 << 16))
    try:
        os.close(os.open(probe, os.O_RDONLY | os.O_DIRECT))
    except OSError as error:
        pytest.skip(f"{directory} refuses O_DIRECT ({error.strerror}); set UCALL_TEST_DIRECT_DIRECTORY to a disk")
    finally:
        probe.unlink()
    yield directory
    if base:
        shutil.rmtree(directory)
