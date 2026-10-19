"""Every `UCALL_*` variable the `test/*.py` suites read, parsed once at import into `SETTINGS`."""

from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass


def env_text(name: str) -> str | None:
    """Reads `name`, or `None` when it is unset or empty."""
    return os.environ.get(name) or None


_REQUESTED_SEED = os.environ.get("UCALL_SEED") or "42"
if _REQUESTED_SEED == "random":
    _RUN_SEED = secrets.randbits(32)
elif _REQUESTED_SEED.isascii() and _REQUESTED_SEED.isdigit() and int(_REQUESTED_SEED) < 2**32:
    _RUN_SEED = int(_REQUESTED_SEED)
else:
    raise SystemExit(f'UCALL_SEED="{_REQUESTED_SEED}" does not parse, expected an unsigned integer or random')


@dataclass(frozen=True)
class Settings:
    """Every `UCALL_*` variable the suites read, parsed once at import."""

    seed: int
    filter: str
    filter_pattern: re.Pattern[str] | None

    def selects(self, name: str) -> bool:
        """Whether `UCALL_FILTER` selects the test `name`, as a regex or else as a substring."""
        return bool(self.filter_pattern.search(name)) if self.filter_pattern else self.filter in name


def read_settings() -> Settings:
    """Reads every `UCALL_*` variable, exiting with status 1 on the first that does not parse."""
    filter = env_text("UCALL_FILTER") or ""
    try:
        filter_pattern = re.compile(filter) if filter else None
    except re.error:
        filter_pattern = None
    return Settings(seed=_RUN_SEED, filter=filter, filter_pattern=filter_pattern)


SETTINGS = read_settings()
