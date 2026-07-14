"""Unit tests for notebook.cache — check/write helpers + extractor integration (Phase 2).

These tests don't need Ghidra — they test the cache pipeline with fake data.

Extractor families are guaranteed registered by conftest.py's session fixture.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from ghidra_nexus.notebook import Notebook
from ghidra_nexus.notebook.cache import (
    check_decompile_cache,
    check_disasm_cache,
    check_xrefs_cache,
    resolve_binary_id,
    write_decompile_cache,
    write_disasm_cache,
    write_xrefs_cache,
)
from ghidra_nexus.notebook.extractors import extract_for


@pytest.fixture
def nb(tmp_path: Path) -> Notebook:
    p = tmp_path / "nb.sqlite"
    n = Notebook.open(p)
    yield n
    n.close_quietly()


@pytest.fixture
def bid(nb):
    return nb.binaries.upsert(name="find.exe", sha256="abc123", arch="x86_64", function_count=27)


class TestDecompileCache:
    def test_miss_then_hit(self, nb, bid):
        rva = "0x1000"
        # Cache miss → None
        assert check_decompile_cache(nb, binary_id=bid, rva=rva, current_gen=0, offset=0, limit=200) is None

        # Write
        write_decompile_cache(nb, binary_id=bid, binary_name="find.exe", binary_sha256="abc123",
                              rva=rva, current_gen=0,
                              result={"name": "main", "code": "int main() {\n  return 0;\n}", "lines": 3,
                                      "decompiler_status": "decompiled", "signature": "int main(void)"})

        # Cache hit
        hit = check_decompile_cache(nb, binary_id=bid, rva=rva, current_gen=0, offset=0, limit=200)
        assert hit is not None
        assert hit["cached"] is True
        assert "int main" in hit["code"]
        assert hit["lines"] == 3

    def test_stale_generation_returns_miss(self, nb, bid):
        rva = "0x1000"
        write_decompile_cache(nb, binary_id=bid, binary_name="find.exe", binary_sha256="abc123",
                              rva=rva, current_gen=0, result={"name": "f", "code": "x", "lines": 1})
        # Generation 0 stored; query with generation 1 → stale → miss
        assert check_decompile_cache(nb, binary_id=bid, rva=rva, current_gen=1, offset=0, limit=200) is None

    def test_view_written_on_put(self, nb, bid):
        rva = "0x1000"
        write_decompile_cache(nb, binary_id=bid, binary_name="find.exe", binary_sha256="abc123",
                              rva=rva, current_gen=0,
                              result={"name": "main", "code": "int main() { CreateFileW(); }", "lines": 2,
                                      "decompiler_status": "decompiled"})
        v = nb.views.get_for(bid, rva, "decompile")
        assert v is not None, "artifact_views row must be inserted by write-through"
        entities = json.loads(v["key_entities"])
        api_names = [e["value"] for e in entities if e["kind"] == "api"]
        assert "CreateFileW" in api_names

    def test_fts_indexed_on_put(self, nb, bid):
        rva = "0x1000"
        write_decompile_cache(nb, binary_id=bid, binary_name="find.exe", binary_sha256="abc123",
                              rva=rva, current_gen=0,
                              result={"name": "main", "code": "int main() { CreateFileW(); }", "lines": 2,
                                      "decompiler_status": "decompiled"})
        hits = nb.search.query("CreateFileW", binary_id=bid, kind="decompile")
        assert len(hits) >= 1, "FTS must find extracted API entity"

    def test_embed_queue_enqueued(self, nb, bid):
        rva = "0x1000"
        write_decompile_cache(nb, binary_id=bid, binary_name="find.exe", binary_sha256="abc123",
                              rva=rva, current_gen=0,
                              result={"name": "main", "code": "int main() {}", "lines": 1,
                                      "decompiler_status": "decompiled"})
        pending = nb.embed_queue.pending()
        assert len(pending) >= 1, "embed_queue must receive a pending row on cache put"

    def test_write_failure_does_not_raise(self, nb, bid):
        # Pass invalid result — write should catch and log, never raise.
        write_decompile_cache(nb, binary_id=999999, binary_name="nope", binary_sha256="x",
                              rva="0x0", current_gen=0,
                              result={"name": "x", "code": "x", "lines": 1})
        # No exception → the handler call continues


class TestDisasmCache:
    def test_miss_then_hit(self, nb, bid):
        rva = "0x1000"
        assert check_disasm_cache(nb, binary_id=bid, rva=rva, current_gen=0, offset=0, limit=40) is None
        write_disasm_cache(nb, binary_id=bid, binary_name="find.exe", rva=rva, current_gen=0,
                           result={"listing": "push rbp\nmov rbp, rsp\nret", "count": 3, "instruction_count": 3})
        hit = check_disasm_cache(nb, binary_id=bid, rva=rva, current_gen=0, offset=0, limit=40)
        assert hit is not None
        assert hit["cached"] is True


class TestXrefsCache:
    def test_miss_then_hit(self, nb, bid):
        rva = "0x401200"  # This is the target being referenced.
        assert check_xrefs_cache(nb, binary_id=bid, rva=rva, offset=0, limit=50) is None
        write_xrefs_cache(nb, binary_id=bid, binary_name="find.exe", rva=rva, current_gen=0,
                          result={"cross_references": [
                              {"from_address": "0x401000", "to_address": rva, "type": "code", "function_name": "main"},
                          ]})
        hit = check_xrefs_cache(nb, binary_id=bid, rva=rva, offset=0, limit=50)
        assert hit is not None
        assert hit["cached"] is True


class TestExtractorIntegration:
    """Verify all registered extractor families produce valid views."""
    def test_decompile_extractor_registered(self):
        v = extract_for("decompile", {"name": "f", "code": "int main() { return 0; }", "lines": 1})
        assert v is not None
        assert v.summary

    def test_disasm_extractor_registered(self):
        v = extract_for("disasm", {"name": "f", "address": "0x401000", "listing": "push rbp\ncall 0x402000\nret", "count": 3})
        assert v is not None
        assert "0x401000" in v.summary

    def test_xrefs_extractor_registered(self):
        v = extract_for("xrefs", {"target": "0x401000", "cross_references": [
            {"function_name": "main", "type": "code"}, {"function_name": "foo", "type": "data"}]})
        assert v is not None
        assert "main" in v.summary

    def test_strings_extractor_registered(self):
        v = extract_for("strings", {"strings": [{"value": "password"}, {"value": "error"}]})
        assert v is not None
        assert "password" in v.summary

    def test_section_health_extractor_registered(self):
        v = extract_for("section_health", {"results": [
            {"name": ".text", "classification": "encrypted", "recommendation": "dump_runtime"}]})
        assert v is not None
        assert "encrypted" in v.summary
