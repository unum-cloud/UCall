"""The hooks pytest loads for itself: the report header, the filter, and parametrized names.

Settings, matrices and fixtures live in `base`, loaded here as a plugin.

File: test/conftest.py
Author: Ash Vardanian
Date: October 19, 2026
"""

from enum import IntEnum

import pytest
from base import SETTINGS

import ucall

pytest_plugins = ["base"]


def pytest_report_header() -> list[str]:
    """The build this run exercises, printed where pytest prints its own header."""
    pattern = getattr(SETTINGS.filter, "pattern", SETTINGS.filter)
    return [
        f"- UCall: {ucall.__version__} from {ucall.lib.__file__}",
        f"- Seed: {SETTINGS.seed}",
        f"- Filter: {pattern or 'none'}",
    ]


def pytest_make_parametrize_id(config: pytest.Config, val: object, argname: str) -> str | None:
    """Names a parametrized enum by its member, such as `linux_epollaio`, where pytest would print its value."""
    return val.name.lower() if isinstance(val, IntEnum) else None


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Keeps only the tests whose node id `UCALL_FILTER` selects, on top of any `-k`."""
    deselected = [item for item in items if not SETTINGS.selects(item.nodeid)]
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = [item for item in items if SETTINGS.selects(item.nodeid)]
