"""Unit tests for port_verifications persistence + FTS knowledge recall."""

from __future__ import annotations

from pathlib import Path

import pytest

from ghidra_nexus.notebook import Notebook


@pytest.fixture
def nb(tmp_path: Path) -> Notebook:
    p = tmp_path / "nb.sqlite"
    n = Notebook.open(p)
    yield n
    n.close_quietly()


@pytest.fixture
def bid(nb):
    return nb.binaries.upsert(name="sample.exe", sha256="abc123", arch="x86", function_count=10)


class TestPortVerifications:
    def test_put_and_latest(self, nb, bid):
        nb.port_verifications.put(
            binary_id=bid,
            rva="0x7280",
            signature="int __thiscall Lock(int flags, uint count)",
            signature_hash="deadbeef",
            verdict="pass",
            checks=[{"name": "calling_convention", "status": "pass"}],
        )
        latest = nb.port_verifications.latest_for(bid, "0x7280")
        assert latest is not None
        assert latest["verdict"] == "pass"
        assert "calling_convention" in latest["checks_json"]

    def test_latest_returns_most_recent(self, nb, bid):
        for verdict in ("fail", "pass"):
            nb.port_verifications.put(
                binary_id=bid,
                rva="0x7280",
                signature="sig",
                signature_hash="h",
                verdict=verdict,
                checks=[],
            )
        assert nb.port_verifications.latest_for(bid, "0x7280")["verdict"] == "pass"
        assert nb.port_verifications.count_for_binary(bid) == 2

    def test_verdict_recallable_via_fts(self, nb, bid):
        nb.port_verifications.put(
            binary_id=bid,
            rva="0x72ac",
            signature="int __thiscall GeometryLock(int flags)",
            signature_hash="h",
            verdict="fail",
            checks=[{"name": "stack_param_count", "status": "fail"}],
        )
        hits = nb.search.query("GeometryLock", binary_id=bid, kind="port_verification")
        assert hits, "expected the recorded verdict to be FTS-searchable"


class TestKnowledgePlaneFts:
    def test_hypothesis_is_indexed(self, nb, bid):
        nb.hypotheses.create(
            text="Lock uses a nonstandard push order at the vtable call",
            binary_id=bid,
        )
        hits = nb.search.query("nonstandard", binary_id=bid, kind="hypothesis")
        assert hits, "hypothesis text should be FTS-searchable"

    def test_hypothesis_update_reindexes(self, nb, bid):
        hid = nb.hypotheses.create(text="preliminary guess", binary_id=bid)
        nb.hypotheses.update(hid, status="confirmed", text="confirmed push order")
        hits = nb.search.query("confirmed", binary_id=bid, kind="hypothesis")
        assert hits

    def test_alias_is_indexed(self, nb, bid):
        nb.aliases.upsert(
            binary_id=bid,
            rva="0x7280",
            name="GeometryCache_LockCopy",
            notes="vtable slot 0x2c",
        )
        hits = nb.search.query("vtable", binary_id=bid, kind="alias")
        assert hits, "alias notes should be FTS-searchable"

    def test_error_breadcrumb_is_indexed(self, nb, bid):
        nb.breadcrumbs.insert(
            binary_id=bid,
            session_id="s1",
            tool="verify_port",
            summary="zorkmid parse blew up",
            error_code="invalid_params",
        )
        hits = nb.search.query("zorkmid", binary_id=bid, kind="breadcrumb_error")
        assert hits, "failure breadcrumbs should be FTS-searchable"

    def test_plain_breadcrumb_is_not_indexed(self, nb, bid):
        nb.breadcrumbs.insert(
            binary_id=bid,
            session_id="s1",
            tool="disassemble",
            summary="quixotic routine inspection",
        )
        hits = nb.search.query("quixotic", binary_id=bid)
        assert not hits, "plain breadcrumbs must not flood the FTS index"
