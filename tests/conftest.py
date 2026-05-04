"""Shared fixtures.

Tests run offline by default. Live tests (real OpenAI / Anthropic) only run
when the ``RUN_LIVE=1`` env var is set.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Make ``src/`` importable without installing the package.
_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))


def pytest_collection_modifyitems(config, items):
    if os.getenv("RUN_LIVE") == "1":
        return
    skip_live = pytest.mark.skip(reason="live tests gated on RUN_LIVE=1")
    for item in items:
        if "live" in item.keywords or "/tests/live/" in str(item.fspath).replace("\\", "/"):
            item.add_marker(skip_live)


@pytest.fixture
def mock_pass():
    from prompt_protector import MockAuditor

    return MockAuditor()


@pytest.fixture
def mock_fail_on():
    from prompt_protector import MockAuditor

    def make(substr: str):
        return MockAuditor(fail_substrings=[substr])

    return make
