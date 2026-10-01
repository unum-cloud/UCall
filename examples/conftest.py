"""The report header, the `UCALL_FILTER` hook and the seeding fixtures every `examples/test_*.py` suite inherits."""

from __future__ import annotations

import random

import pytest
from base import SETTINGS


def pytest_report_header() -> list[str]:
    """Echoes every setting in the grammar it parses, where pytest prints its own header."""
    return [f"- Seed: {SETTINGS.seed}", f"- Filter: {SETTINGS.filter or 'none'}"]


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Keeps only the tests whose node id `UCALL_FILTER` selects, on top of any `-k`."""
    deselected = [item for item in items if not SETTINGS.selects(item.nodeid)]
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = [item for item in items if SETTINGS.selects(item.nodeid)]


@pytest.fixture
def seed() -> int:
    """The seed of this run, 42 unless `UCALL_SEED` names another or is `random`."""
    return SETTINGS.seed


@pytest.fixture
def rng(seed: int) -> random.Random:
    """An RNG private to this test, so a neighbour's draws cannot shift this one's."""
    return random.Random(seed)
