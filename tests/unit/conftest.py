"""Session-level fixtures: notebook extractor registry + embed-worker opt-out.

``test_notebook_extractors.py`` uses module-scoped fixtures that reset the global
registry. Test modules that run later need the extractors re-registered.

This conftest loads at the unit/ level so all unit tests start with a complete
extractor registry. It also disables the background embed worker to keep
asyncio event loops in unit tests from racing with a daemon SQLite thread.
"""

import os

import pytest

# Disable the embed worker daemon thread during the unit suite. The daemon
# shares the notebook SQLite connection; combined with WAL mode it can race
# the asyncio event loop in tight async tests.
os.environ.setdefault("NEXUS_DISABLE_EMBED_WORKER", "1")


@pytest.fixture(scope="session", autouse=True)
def _ensure_extractor_families():
    """Guarantee all known extractor families are in the global registry."""
    from ghidra_nexus.notebook.extractors.base import register
    from ghidra_nexus.notebook.extractors.decompile import DecompileExtractor
    from ghidra_nexus.notebook.extractors.families import (
        DisasmExtractor,
        SectionHealthExtractor,
        StringsExtractor,
        XrefsExtractor,
    )

    register(DecompileExtractor())
    register(DisasmExtractor())
    register(XrefsExtractor())
    register(StringsExtractor())
    register(SectionHealthExtractor())
    # This fixture never tears down — we want families permanent.
