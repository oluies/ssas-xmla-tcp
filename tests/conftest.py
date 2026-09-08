"""Shared test fixtures.

Sockets are disabled by pytest configuration, not here, so that a test which
accidentally reaches the network fails loudly rather than silently passing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_bytes():
    """Read a recorded byte fixture, e.g. fixture_bytes('dime/discover_req.bin')."""

    def _read(relative: str) -> bytes:
        return (FIXTURES / relative).read_bytes()

    return _read


@pytest.fixture
def fixture_text():
    """Read a recorded text fixture, e.g. fixture_text('xmla/datasources.xml')."""

    def _read(relative: str) -> str:
        return (FIXTURES / relative).read_text(encoding="utf-8")

    return _read
