"""Session- and function-level fixtures for unit tests.

Three things this conftest guarantees for every unit test:

1. **Extractor registry** is populated. ``test_notebook_extractors.py`` resets
   the registry between tests; everything that runs after needs the families
   re-registered.

2. **Module-level singletons** (``_NOTEBOOK_SINGLETON``, ``_EMBED_WORKER``) are
   reset before each test, so a write-through from test N doesn't leak into
   test N+1's cache check.

3. **Notebook path isolation** — every test gets its own tmp_path-based notebook
   via the ``NEXUS_NOTEBOOK_PATH`` env var. Without this, all tests share one
   notebook file and the first test to call ``decompile_function`` pollutes the
   cache for every subsequent test (this is what caused the
   ``test_decompile_does_not_block_other_tool_calls`` hang).

The embed worker is also disabled by default — its daemon thread shares the
notebook SQLite connection and can race the asyncio event loop in tight async
tests. Set ``NEXUS_DISABLE_EMBED_WORKER=0`` in a specific test if you need it.
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


@pytest.fixture(autouse=True)
def _isolate_notebook(tmp_path, monkeypatch):
    """Give every test its own fresh notebook DB.

    Three things:
      - Set NEXUS_NOTEBOOK_PATH to a per-test tmp file.
      - Reset the module-level _NOTEBOOK_SINGLETON + _EMBED_WORKER so the next
        call re-opens against the new path.
      - Stop any previously-started embed worker daemon thread.

    Tests that need to control the notebook path explicitly can override
    NEXUS_NOTEBOOK_PATH before this fixture runs; ``setdefault`` semantics
    in the env var read ensure we honor an explicit value.
    """
    import ghidra_nexus.mcp_tools as mcp_tools

    # Stop any leftover worker from a previous test (it may still be holding
    # a connection to the previous test's notebook file).
    try:
        mcp_tools._stop_embed_worker()
    except Exception:
        pass
    # Reset the singleton so the next _get_notebook() opens the new path.
    mcp_tools._NOTEBOOK_SINGLETON = None
    mcp_tools._EMBED_WORKER = None

    # Per-test notebook path. monkeypatch undoes this after the test.
    nb_path = tmp_path / "notebook.sqlite"
    monkeypatch.setenv("NEXUS_NOTEBOOK_PATH", str(nb_path))

    yield nb_path

    # Teardown: stop the worker (it now points at a tmp file that's about to
    # vanish), close the notebook connection, and reset singletons so the
    # next test starts clean.
    try:
        nb = mcp_tools._NOTEBOOK_SINGLETON
        if nb is not None:
            nb.close_quietly()
    except Exception:
        pass
    try:
        mcp_tools._stop_embed_worker()
    except Exception:
        pass
    mcp_tools._NOTEBOOK_SINGLETON = None
    mcp_tools._EMBED_WORKER = None
