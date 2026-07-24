"""Unit tests for the call-sites notebook cache (Phase 2 pattern, no JVM)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ghidra_nexus.notebook import Notebook
from ghidra_nexus.notebook.cache import check_callsite_cache, write_callsite_cache


@pytest.fixture
def nb(tmp_path: Path) -> Notebook:
    p = tmp_path / "nb.sqlite"
    n = Notebook.open(p)
    yield n
    n.close_quietly()


@pytest.fixture
def bid(nb):
    return nb.binaries.upsert(name="sample.exe", sha256="abc123", arch="x86", function_count=10)


def _payload() -> dict:
    return {
        "function_name": "sub_887280",
        "function_address": "0x887280",
        "call_sites": [
            {
                "address": "0x8872AC",
                "instruction": "CALL EAX",
                "is_indirect": True,
                "target_name": None,
                "target_address": None,
                "callee_convention": None,
                "callee_param_count": None,
                "stack_args": [
                    {
                        "slot_offset": 0,
                        "source": "eax",
                        "resolved_source": None,
                        "written_at": "0x8872A0",
                        "write_kind": "push",
                    }
                ],
                "other_stack_writes": [],
                "register_args": {},
                "ecx_source": "[eax]",
                "caller_cleanup_bytes": None,
                "inferred_convention": "__thiscall?",
                "confidence": "medium",
                "warnings": [],
            }
        ],
        "total_call_sites": 1,
    }


class TestCallSiteCache:
    def test_miss_then_hit(self, nb, bid):
        rva = "0x7280"
        assert (
            check_callsite_cache(nb, binary_id=bid, rva=rva, current_gen=0, offset=0, limit=20)
            is None
        )

        write_callsite_cache(
            nb,
            binary_id=bid,
            binary_name="sample.exe",
            rva=rva,
            current_gen=0,
            result=_payload(),
        )

        hit = check_callsite_cache(nb, binary_id=bid, rva=rva, current_gen=0, offset=0, limit=20)
        assert hit is not None
        assert hit["cached"] is True
        assert hit["function_name"] == "sub_887280"
        assert hit["total_call_sites"] == 1
        assert hit["call_sites"][0]["address"] == "0x8872AC"
        assert hit["page"]["has_more"] is False

    def test_stale_generation_returns_miss(self, nb, bid):
        rva = "0x7280"
        write_callsite_cache(
            nb,
            binary_id=bid,
            binary_name="sample.exe",
            rva=rva,
            current_gen=0,
            result=_payload(),
        )
        assert (
            check_callsite_cache(nb, binary_id=bid, rva=rva, current_gen=1, offset=0, limit=20)
            is None
        )

    def test_view_written_on_put(self, nb, bid):
        rva = "0x7280"
        write_callsite_cache(
            nb,
            binary_id=bid,
            binary_name="sample.exe",
            rva=rva,
            current_gen=0,
            result=_payload(),
        )
        views = nb.views.get_for(binary_id=bid, rva=rva, kind="call_sites")
        assert views is not None, "expected an artifact view for the call_sites kind"

    def test_delete_old_generations(self, nb, bid):
        rva = "0x7280"
        for gen in range(3):
            write_callsite_cache(
                nb,
                binary_id=bid,
                binary_name="sample.exe",
                rva=rva,
                current_gen=gen,
                result=_payload(),
            )
        deleted = nb.call_sites.delete_old_generations(bid, keep_generations=1)
        assert deleted == 2
        # Latest generation survives.
        hit = check_callsite_cache(nb, binary_id=bid, rva=rva, current_gen=2, offset=0, limit=20)
        assert hit is not None
