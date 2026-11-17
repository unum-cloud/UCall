"""The hooks and fixtures the Python suites share: the report header, the backend sweep, and the
loopback interfaces, polling threads and unbuffered directories servers need.

File: test/conftest.py
Author: Ash Vardanian
Date: October 19, 2026
"""

import collections
import contextlib
import enum
import os
import pathlib
import random
import shutil
import sys
import tempfile
import threading
from collections.abc import Callable, Iterator

import pytest
from base import BACKEND_AXES, BACKENDS, MAX_CASES_PER_TEST, SETTINGS, stream_key

import ucall


def pytest_report_header() -> list[str]:
    """The build this run exercises and its settings, printed where pytest prints its own header."""
    return [
        f"UCall {ucall.__version__} from {ucall.lib.__file__}",
        f"- Seed: {SETTINGS.seed}, scale: {SETTINGS.scale:g}",
    ]


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Runs a case taking `backend` on every backend, skipping those this platform lacks, or once on
    the automatic one when it is marked `any_backend`.
    """
    if "backend" not in metafunc.fixturenames:
        return
    if metafunc.definition.get_closest_marker("any_backend"):
        metafunc.parametrize("backend", [ucall.Backend.AUTOMATIC])
        return
    swept = [
        pytest.param(
            backend,
            marks=() if present else pytest.mark.skip(reason=f"Backend.{backend.name} is refused on this machine"),
        )
        for backend, present in BACKENDS.items()
    ]
    metafunc.parametrize("backend", swept)


# region Shared Pytest
def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Refuses a test whose cases outgrow MAX_CASES_PER_TEST."""
    variants: dict[tuple[str, str], set[str]] = collections.defaultdict(set)
    for item in items:
        callspec = getattr(item, "callspec", None)
        parameters = dict(callspec.params) if callspec is not None else {}
        parameters.pop("__pytest_repeat_step_number", None)
        kept = {key: value for key, value in parameters.items() if key not in BACKEND_AXES}
        variants[(item.module.__name__, getattr(item, "originalname", item.name))].add(repr(kept))
    oversized = [
        f"{module}::{name} has {len(cases)}"
        for (module, name), cases in variants.items()
        if len(cases) > MAX_CASES_PER_TEST
    ]
    if oversized:
        raise pytest.UsageError(f"over MAX_CASES_PER_TEST={MAX_CASES_PER_TEST}: " + "; ".join(oversized))


def pytest_make_parametrize_id(config: pytest.Config, val: object, argname: str) -> str | None:
    """Names enum parameters as the code spells them, `Backend.LINUX_URING618`, so an id greps to its source."""
    return f"{type(val).__name__}.{val.name}" if isinstance(val, enum.Enum) else None


@pytest.fixture
def seed(request: pytest.FixtureRequest) -> int:
    """Share inputs across backends while keeping other parameters and repeat steps distinct."""
    callspec = getattr(request.node, "callspec", None)
    parameters = dict(callspec.params) if callspec is not None else {}
    repeat_step = parameters.pop("__pytest_repeat_step_number", 0)
    name = request.node.originalname or request.node.name
    name += repr({key: value for key, value in parameters.items() if key not in BACKEND_AXES})
    return stream_key(SETTINGS.seed, name, repeat_step)


@pytest.fixture
def rng(seed: int) -> random.Random:
    """A generator private to this test, so a neighbour's draws cannot shift this one's."""
    return random.Random(seed)


@pytest.fixture
def unraisable(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Collects what the interpreter reports as unraisable, like a finalizer's exception, for the test to check."""
    seen: list[object] = []
    monkeypatch.setattr(sys, "unraisablehook", seen.append)
    return seen


# endregion Shared Pytest


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
    """A directory whose files open with `os.O_DIRECT`: under `UCALL_TEST_DIRECT_DIRECTORY`, else `tmp_path`."""
    base = os.environ.get("UCALL_TEST_DIRECT_DIRECTORY")
    directory = pathlib.Path(tempfile.mkdtemp(prefix="ucall-direct-", dir=base)) if base else tmp_path
    probe = directory / "probe.bin"
    probe.write_bytes(bytes(1 << 16))
    try:
        os.close(os.open(probe, os.O_RDONLY | os.O_DIRECT))
    except OSError as error:
        pytest.skip(
            f"O_DIRECT is refused on this machine at {directory}: {error.strerror}; "
            "set UCALL_TEST_DIRECT_DIRECTORY to a disk"
        )
    finally:
        probe.unlink()
    yield directory
    if base:
        shutil.rmtree(directory)
