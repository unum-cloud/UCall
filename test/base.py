"""Settings and matrices the Python suites share: the seed and scale the environment names, and
the backends a server runs on. Fixtures live in `conftest`.

File: test/base.py
Author: Ash Vardanian
Date: October 19, 2026
"""

import os
import random
import sys
from dataclasses import dataclass
from typing import NoReturn

import ucall

# region Shared Settings
_UINT64_MASK = 2**64 - 1


def env_text(variable: str) -> str | None:
    """The stripped text of the environment `variable`, or None when unset or blank."""
    text = os.environ.get(variable, "").strip()
    return text or None


def exit_unparsed(variable: str, text: str, expected: str) -> NoReturn:
    """Stops the session on a setting that does not parse, naming it as the C and C++ suites do."""
    raise SystemExit(f'{variable}="{text}" does not parse, expected {expected}')


def env_seed(variable: str) -> int:
    """An unsigned 64-bit seed: 42 when unset, drawn afresh for `random`."""
    text = env_text(variable)
    if text is None:
        return 42
    if text == "random":
        return random.SystemRandom().getrandbits(64)
    if not text.isdigit() or int(text) > _UINT64_MASK:
        exit_unparsed(variable, text, "an unsigned integer or random")
    return int(text)


def env_real(variable: str, fallback: float) -> float:
    """A positive real, `fallback` when unset."""
    text = env_text(variable)
    if text is None:
        return fallback
    try:
        value = float(text)
    except ValueError:
        value = 0.0
    if not value > 0 or value == float("inf"):
        exit_unparsed(variable, text, "a positive number like 0.1 or 10")
    return value


def env_count(variable: str, fallback: int) -> int:
    """A whole number, `fallback` when unset."""
    text = env_text(variable)
    if text is None:
        return fallback
    if not text.isdigit():
        exit_unparsed(variable, text, "a whole number")
    return int(text)


def env_flag(variable: str, fallback: bool = False) -> bool:
    """A switch, `fallback` when unset: 0, false, off and no turn it off."""
    text = env_text(variable)
    if text is None:
        return fallback
    return text not in {"0", "false", "off", "no"}


def mix(value: int) -> int:
    """SplitMix64's finalizer, a bijection that spreads every input bit over all 64 output bits."""
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & _UINT64_MASK
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & _UINT64_MASK
    return value ^ (value >> 31)


def stream_key(seed: int, name: str, index: int = 0) -> int:
    """The `index`-th stream of the family `name` under `seed`, identical in C, C++, Rust and Mojo."""
    hashed = 0xCBF29CE484222325
    for byte in name.encode():
        hashed = ((hashed ^ byte) * 0x100000001B3) & _UINT64_MASK
    return mix((mix(seed ^ hashed) + index) & _UINT64_MASK)


# endregion Shared Settings


@dataclass(frozen=True)
class Settings:
    """Every `UCALL_*` variable the Python suites read, parsed once at import."""

    seed: int
    scale: float


SETTINGS = Settings(seed=env_seed("UCALL_SEED"), scale=env_real("UCALL_SCALE", 1.0))

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

BACKEND_AXES = {"backend"}
"""The axes the seed and the case cap leave out, so every backend draws the same inputs."""

MAX_CASES_PER_TEST = 1
"""The most cases one test function may expand to beside its backends, today's largest, so a new
axis cannot multiply a matrix past it unnoticed.
"""
