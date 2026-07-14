"""Unit tests for notebook.vec (Phase 1 / F12).

These run on whatever the host sqlite-vec wheel provides. If sqlite-vec isn't
installed (uncommon in this project, since we depend on it), we skip.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from ghidra_nexus.notebook.vec import (
    EMBED_DIM,
    EMBED_MODEL_ID,
    VecStatus,
    try_enable_vec,
)


@pytest.fixture
def fresh_db(tmp_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(tmp_path / "vec_probe.sqlite"))
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        yield conn
    finally:
        conn.close()


class TestTryEnableVec:
    def test_returns_status_dataclass(self, fresh_db):
        status = try_enable_vec(fresh_db)
        assert isinstance(status, VecStatus)
        assert status.model_default == EMBED_MODEL_ID
        assert status.dim == EMBED_DIM

    def test_never_raises(self, fresh_db):
        # Smoke: calling repeatedly does not raise.
        for _ in range(3):
            try_enable_vec(fresh_db)

    def test_sets_available_correctly(self, fresh_db):
        status = try_enable_vec(fresh_db)
        # We installed sqlite-vec as a dep; on a working system this should
        # be True. If the host doesn't have the binary wheel, status is False
        # and we skip the strict assertion.
        if not status.available:
            pytest.skip(
                f"sqlite-vec probe did not load: {status.error!r}; "
                "OK if running on a host without the binary wheel"
            )
        assert status.available is True
        assert status.error is None

    def test_status_shape_on_failure(self, fresh_db):
        status = try_enable_vec(fresh_db)
        if status.available:
            pytest.skip("vec loaded; can't test failure shape")
        # When not available, error is set and is non-empty.
        assert status.error
        assert "sqlite-vec" in status.error.lower() or "vec" in status.error.lower()


class TestConstants:
    def test_embed_dim(self):
        # The plan pins 384-d (MiniLM). Phase 3 will refuse to query with
        # mismatched dim — keep this assertion as a guard against silent change.
        assert EMBED_DIM == 384

    def test_embed_model_default(self):
        assert EMBED_MODEL_ID == "all-MiniLM-L6-v2"
