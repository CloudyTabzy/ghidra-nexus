"""Unit tests for notebook schema, migrations, and sub-manager CRUD (Phase 1)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghidra_nexus.notebook import Notebook

SCHEMA_VERSION = 4


@pytest.fixture
def nb(tmp_path: Path) -> Notebook:
    p = tmp_path / "nb.sqlite"
    n = Notebook.open(p)
    yield n
    n.close_quietly()


class TestMigrations:
    def test_user_version_is_one_on_fresh(self, nb):
        assert nb._conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION

    def test_reopen_is_idempotent(self, tmp_path):
        p = tmp_path / "nb.sqlite"
        nb1 = Notebook.open(p)
        ver1 = nb1._conn.execute("PRAGMA user_version").fetchone()[0]
        nb1.close()
        nb2 = Notebook.open(p)
        ver2 = nb2._conn.execute("PRAGMA user_version").fetchone()[0]
        nb2.close_quietly()
        assert ver1 == ver2 == SCHEMA_VERSION

    def test_all_tables_exist(self, nb):
        tables = {
            "binaries", "functions", "decompiles", "disassemblies",
            "call_sites", "port_verifications",
            "xrefs", "strings", "breadcrumbs", "breadcrumbs_archive",
            "aliases", "hypotheses", "artifact_views", "embeddings",
            "embed_queue", "fts",  # virtual table
        }
        rows = nb._conn.execute(
            "SELECT name FROM sqlite_master WHERE type in ('table', 'view')"
        ).fetchall()
        found = {r[0] for r in rows}
        missing = tables - found
        assert not missing, f"missing tables: {missing}"

    def test_fts_virtual_table_exists(self, nb):
        # FTS5 may show up as 'fts', 'fts_content', 'fts_idx', 'fts_data'
        rows = nb._conn.execute(
            "SELECT name FROM sqlite_master WHERE name LIKE 'fts%'"
        ).fetchall()
        assert rows, "FTS5 virtual tables not found"


class TestBinariesManager:
    def test_upsert_returns_id(self, nb):
        bid = nb.binaries.upsert(name="test.dll", sha256="abc", arch="x86_64")
        assert isinstance(bid, int)
        assert bid > 0

    def test_upsert_is_idempotent(self, nb):
        bid1 = nb.binaries.upsert(name="test.dll", sha256="abc")
        bid2 = nb.binaries.upsert(name="test.dll", sha256="def")
        assert bid1 == bid2

    def test_upsert_populates_scale(self, nb):
        bid = nb.binaries.upsert(
            name="big.dll", sha256="x", size_bytes=100 * 1024 * 1024, function_count=200_000
        )
        b = nb.binaries.get_by_id(bid)
        assert b["binary_class"] == "very_large"
        notes = json.loads(b["reliability_notes"])
        assert isinstance(notes, list)
        assert any("notebook_preheat" in n for n in notes)

    def test_get_returns_row(self, nb):
        nb.binaries.upsert(name="find.exe", sha256="abc", arch="x86_64")
        b = nb.binaries.get("find.exe")
        assert b is not None
        assert b["name"] == "find.exe"
        assert b["sha256"] == "abc"

    def test_get_missing_returns_none(self, nb):
        assert nb.binaries.get("nope") is None

    def test_all_returns_sorted(self, nb):
        nb.binaries.upsert(name="z.dll", sha256="z")
        nb.binaries.upsert(name="a.dll", sha256="a")
        names = [b["name"] for b in nb.binaries.all()]
        assert names == ["a.dll", "z.dll"]

    def test_bump_generation(self, nb):
        nb.binaries.upsert(name="f.exe", sha256="s")
        assert nb.binaries.bump_generation("f.exe") == 1
        assert nb.binaries.bump_generation("f.exe") == 2

    def test_mark_analysis_ready(self, nb):
        nb.binaries.upsert(name="f.exe", sha256="s")
        nb.binaries.mark_analysis_ready("f.exe")
        b = nb.binaries.get("f.exe")
        assert b["analysis_ready"] == 1

    def test_mark_analysis_ready_updates_function_count(self, nb):
        nb.binaries.upsert(name="f.exe", sha256="s", function_count=0)
        nb.binaries.mark_analysis_ready("f.exe", function_count=42)
        b = nb.binaries.get("f.exe")
        assert b["analysis_ready"] == 1
        assert b["function_count"] == 42


class TestFunctionsManager:
    def _setup(self, nb):
        bid = nb.binaries.upsert(name="f.exe", sha256="s", arch="x86_64")
        return bid

    def test_upsert_and_get(self, nb):
        bid = self._setup(nb)
        nb.functions.upsert(binary_id=bid, rva="0x1000", name="main", size=512, quality="ok")
        f = nb.functions.get(bid, "0x1000")
        assert f["name"] == "main"
        assert f["quality"] == "ok"

    def test_upsert_updates_existing(self, nb):
        bid = self._setup(nb)
        nb.functions.upsert(binary_id=bid, rva="0x1000", name="old_name", quality="ok")
        nb.functions.upsert(binary_id=bid, rva="0x1000", name="new_name", quality="ok")
        f = nb.functions.get(bid, "0x1000")
        assert f["name"] == "new_name"
        assert f["quality"] == "ok"

    def test_list_with_limit(self, nb):
        bid = self._setup(nb)
        for i in range(10):
            nb.functions.upsert(binary_id=bid, rva=f"0x{i*0x100:x}", name=f"func_{i}")
        funcs = nb.functions.list(bid, offset=0, limit=3)
        assert len(funcs) == 3

    def test_set_quality(self, nb):
        bid = self._setup(nb)
        nb.functions.upsert(binary_id=bid, rva="0x1000", name="stub")
        nb.functions.set_quality(bid, "0x1000", "stub")
        assert nb.functions.get(bid, "0x1000")["quality"] == "stub"


class TestDecompilesManager:
    def _setup(self, nb):
        return nb.binaries.upsert(name="f.exe", sha256="s")

    def test_put_and_get(self, nb):
        bid = self._setup(nb)
        code = "int main() {\n  return 0;\n}"
        rid = nb.decompiles.put(binary_id=bid, rva="0x1000", code=code, lines=3)
        assert rid > 0
        row = nb.decompiles.get(bid, "0x1000")
        assert row is not None
        assert row["lines"] == 3
        assert "code_text" in row
        assert "int main" in row["code_text"]

    def test_get_latest_generation(self, nb):
        bid = self._setup(nb)
        nb.decompiles.put(binary_id=bid, rva="0x1000", code="v1", lines=1, analysis_generation=0)
        nb.decompiles.put(binary_id=bid, rva="0x1000", code="v2", lines=1, analysis_generation=1)
        row = nb.decompiles.get(bid, "0x1000")
        assert "v2" in row["code_text"]

    def test_blob_is_gzipped(self, nb):
        bid = self._setup(nb)
        nb.decompiles.put(binary_id=bid, rva="0x1000", code="x" * 1000, lines=10)
        raw = nb._conn.execute(
            "SELECT code FROM decompiles WHERE binary_id = ? AND rva = ? ORDER BY analysis_generation DESC LIMIT 1",
            (bid, "0x1000"),
        ).fetchone()[0]
        assert raw[:2] == b"\x1f\x8b", "stored blob must be gzipped"


class TestBreadcrumbsManager:
    def test_insert_and_recent(self, nb):
        nb.breadcrumbs.insert(
            session_id="s1", tool="decompile_function", summary="decompiled main", rva="0x1000"
        )
        crumbs = nb.breadcrumbs.recent(session_id="s1")
        assert len(crumbs) >= 1
        assert crumbs[0]["tool"] == "decompile_function"

    def test_summary_truncates_to_256(self, nb):
        long_msg = "x" * 500
        nb.breadcrumbs.insert(session_id="s1", tool="x", summary=long_msg)
        crumb = nb.breadcrumbs.recent(session_id="s1")[0]
        assert len(crumb["summary"]) <= 256


class TestAliasesManager:
    def _setup(self, nb):
        return nb.binaries.upsert(name="f.exe", sha256="s")

    def test_upsert_and_get(self, nb):
        bid = self._setup(nb)
        nb.aliases.upsert(binary_id=bid, rva="0x1000", name="SpeechDispatcher", tags=["audio"], status="confirmed")
        a = nb.aliases.get(bid, "0x1000")
        assert a["name"] == "SpeechDispatcher"
        tags = json.loads(a["tags"])
        assert "audio" in tags


class TestHypothesesManager:
    def test_create_and_get(self, nb):
        hid = nb.hypotheses.create(text="main spawns 4 workers", status="open")
        h = nb.hypotheses.get(hid)
        assert h is not None
        assert h["text"] == "main spawns 4 workers"
        assert h["status"] == "open"

    def test_update_status(self, nb):
        hid = nb.hypotheses.create(text="test", status="open")
        nb.hypotheses.update(hid, status="confirmed")
        assert nb.hypotheses.get(hid)["status"] == "confirmed"

    def test_list_by_status(self, nb):
        nb.hypotheses.create(text="open1", status="open")
        nb.hypotheses.create(text="confirmed1", status="confirmed")
        assert len(nb.hypotheses.list(status="confirmed")) == 1


class TestArtifactViewsManager:
    def _setup(self, nb):
        return nb.binaries.upsert(name="f.exe", sha256="s")

    def test_upsert_and_get(self, nb):
        bid = self._setup(nb)
        vid = nb.views.upsert(
            binary_id=bid, rva="0x1000", kind="decompile",
            summary="Function main, 3 lines.",
            key_entities=json.dumps([{"kind": "api", "value": "CreateFileW"}]),
            source_table="decompiles", source_row_id=1,
        )
        assert vid > 0
        v = nb.views.get_for(bid, "0x1000", "decompile")
        assert v is not None
        entities = json.loads(v["key_entities"])
        assert entities[0]["kind"] == "api"


class TestEmbeddingsManager:
    def _setup(self, nb):
        return nb.binaries.upsert(name="f.exe", sha256="s")

    def test_insert(self, nb):
        bid = self._setup(nb)
        eid = nb.embeddings.insert(
            binary_id=bid, rva="0x1000", kind="decompile",
            model="all-MiniLM-L6-v2", dim=384, embedder_version="0.1.9",
        )
        assert eid > 0

    def test_count(self, nb):
        bid = self._setup(nb)
        nb.embeddings.insert(binary_id=bid, rva="0x1000", kind="decompile", model="m", dim=384, embedder_version="v1")
        assert nb.embeddings.count_for_binary(bid) == 1


class TestFTS:
    def _setup(self, nb):
        return nb.binaries.upsert(name="f.exe", sha256="s")

    def test_index_and_search(self, nb):
        bid = self._setup(nb)
        nb.search.upsert(kind="decompile", binary_id=bid, rva="0x1000", name="main", body="CreateFileW ReadFile CloseHandle")
        hits = nb.search.query("CreateFileW", binary_id=bid, kind="decompile")
        assert len(hits) >= 1
        assert hits[0]["name"] == "main"

    def test_search_project_wide(self, nb):
        bid = self._setup(nb)
        nb.search.upsert(kind="decompile", binary_id=bid, rva="0x1000", name="f1", body="malloc")
        hits = nb.search.query("malloc")
        assert any("f1" in (h["name"] or "") for h in hits)


class TestCascadeDelete:
    def test_delete_binary_cascades(self, nb):
        bid = nb.binaries.upsert(name="f.exe", sha256="s")
        nb.functions.upsert(binary_id=bid, rva="0x1000", name="main")
        nb.decompiles.put(binary_id=bid, rva="0x1000", code="x", lines=1)
        with nb.transaction() as conn:
            conn.execute("DELETE FROM binaries WHERE id = ?", (bid,))
        assert nb.functions.get(bid, "0x1000") is None
        assert nb.decompiles.get(bid, "0x1000") is None
