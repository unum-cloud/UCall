"""Fixtures the Python suites share: the backends a server runs on, loopback interfaces, and
polling threads.

File: test/conftest.py
Author: Ash Vardanian
Date: October 19, 2026
"""

import contextlib
import os
import pathlib
import shutil
import sys
import tempfile
import threading
from collections.abc import Callable, Iterator
from enum import IntEnum

import pytest

import ucall


def pytest_report_header() -> list[str]:
    """The build this run exercises, printed where pytest prints its own header."""
    return [f"- UCall: {ucall.__version__} from {ucall.lib.__file__}"]


def pytest_make_parametrize_id(config: pytest.Config, val: object, argname: str) -> str | None:
    """Names a parametrized enum by its member, such as `linux_epollaio`, where pytest would print its value."""
    return val.name.lower() if isinstance(val, IntEnum) else None


@pytest.fixture(
    params=[
        ucall.Backend.POSIX,
        ucall.Backend.LINUX_EPOLLAIO,
        ucall.Backend.LINUX_URING612,
        ucall.Backend.LINUX_URING618,
    ]
)
def backend(request: pytest.FixtureRequest) -> ucall.Backend:
    """Runs a server test on each backend this platform has."""
    if request.param != ucall.Backend.POSIX and not sys.platform.startswith("linux"):
        pytest.skip("epoll and io_uring are Linux backends")
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
