"""Unit tests for the pure call-site stack analyzer (no JVM required)."""

from __future__ import annotations

from ghidra_nexus.callsite_analysis import InsnRecord, analyze_call_sites


def _insn(addr, mnemonic, operands, **flags) -> InsnRecord:
    return InsnRecord(
        address=addr,
        mnemonic=mnemonic,
        operands=list(operands),
        **flags,
    )


def _feedback_887280_records() -> list[InsnRecord]:
    """The exact sequence from the hook-porting field report (0x887280).

    Indirect vtable call with a non-standard push order: Source is pushed as
    the first stack argument even though ECX also carries object state.
    """
    return [
        _insn("0x887290", "PUSH", ["ebp"]),
        _insn("0x887291", "LEA", ["edx", "[esp + 0x14]"]),
        _insn("0x887295", "PUSH", ["edx"]),
        _insn("0x887296", "MOV", ["edx", "[esp + 0x18]"]),
        _insn("0x88729A", "PUSH", ["edi"]),
        _insn("0x88729B", "MOV", ["esi", "ecx"]),
        _insn("0x88729D", "MOV", ["ecx", "[eax]"]),
        _insn("0x88729F", "PUSH", ["edx"]),
        _insn("0x8872A0", "PUSH", ["eax"]),
        _insn("0x8872A1", "MOV", ["eax", "[ecx + 0x2c]"]),
        _insn("0x8872A4", "MOV", ["[esp + 0x24]", "0x0"]),
        _insn("0x8872AC", "CALL", ["eax"], is_call=True, is_indirect_call=True),
    ]


class TestFeedbackSequence:
    def test_five_stack_args_in_callee_order(self):
        sites = analyze_call_sites(_feedback_887280_records(), pointer_size=4)
        assert len(sites) == 1
        site = sites[0]
        assert site.address == "0x8872AC"
        assert site.is_indirect is True

        slots = [(w.slot_offset, w.source) for w in site.stack_args]
        assert slots == [
            (0x00, "eax"),  # Source (arg1)
            (0x04, "edx"),  # flags (arg2)
            (0x08, "edi"),  # count (arg3)
            (0x0C, "edx"),  # &local_var (arg4)
            (0x10, "ebp"),  # arg2/flags (arg5)
        ]

    def test_register_resolution_normalizes_to_call_time_frame(self):
        site = analyze_call_sites(_feedback_887280_records(), pointer_size=4)[0]
        by_slot = {w.slot_offset: w for w in site.stack_args}
        # mov edx, [esp+0x18] executed when esp was 0x0c above the call frame.
        assert by_slot[0x04].resolved_source == "[sp+0x24]"
        # lea edx, [esp+0x14] executed when esp was 0x10 above the call frame.
        assert by_slot[0x0C].resolved_source == "&[sp+0x24]"

    def test_local_spill_goes_to_other_writes(self):
        site = analyze_call_sites(_feedback_887280_records(), pointer_size=4)[0]
        assert [(w.slot_offset, w.source) for w in site.other_stack_writes] == [(0x24, "0x0")]

    def test_thiscall_inference_with_ecx_evidence(self):
        site = analyze_call_sites(_feedback_887280_records(), pointer_size=4)[0]
        assert site.ecx_source == "[eax]"
        assert site.inferred_convention == "__thiscall?"
        assert site.confidence == "medium"


class TestDirectCalls:
    def test_known_callee_matching_params_is_high_confidence(self):
        records = [
            _insn("0x1000", "PUSH", ["0x2"]),
            _insn("0x1002", "PUSH", ["0x1"]),
            _insn(
                "0x1004",
                "CALL",
                ["foo"],
                is_call=True,
                target_name="foo",
                target_address="0x2000",
                callee_convention="__cdecl",
                callee_param_count=2,
            ),
            _insn("0x1009", "ADD", ["esp", "0x8"]),
        ]
        site = analyze_call_sites(records, pointer_size=4)[0]
        assert site.is_indirect is False
        assert site.inferred_convention == "__cdecl"
        assert site.confidence == "high"
        assert site.caller_cleanup_bytes == 8
        assert site.warnings == []

    def test_known_callee_param_mismatch_warns(self):
        records = [
            _insn("0x1000", "PUSH", ["eax"]),
            _insn("0x1001", "PUSH", ["ebx"]),
            _insn("0x1002", "PUSH", ["ecx"]),
            _insn(
                "0x1003",
                "CALL",
                ["foo"],
                is_call=True,
                target_name="foo",
                target_address="0x2000",
                callee_convention="__stdcall",
                callee_param_count=1,
            ),
        ]
        site = analyze_call_sites(records, pointer_size=4)[0]
        assert site.confidence == "medium"
        assert any("3 stack arg" in w and "1 parameter" in w for w in site.warnings)


class TestMovSlotStyle:
    def test_mov_slot_args_with_cdecl_cleanup(self):
        records = [
            _insn("0x1000", "MOV", ["[esp]", "eax"]),
            _insn("0x1003", "MOV", ["[esp + 0x4]", "0x5"]),
            _insn("0x100B", "CALL", ["eax"], is_call=True, is_indirect_call=True),
            _insn("0x100D", "ADD", ["esp", "0x8"]),
        ]
        site = analyze_call_sites(records, pointer_size=4)[0]
        assert [(w.slot_offset, w.source) for w in site.stack_args] == [
            (0, "eax"),
            (4, "0x5"),
        ]
        assert site.inferred_convention == "__cdecl?"
        assert site.confidence == "medium"

    def test_interleaved_push_and_mov_slot(self):
        # mov [esp+4] executes after a push: it writes the *second* arg slot
        # in the call-time frame even though the push came first in code order.
        records = [
            _insn("0x1000", "PUSH", ["eax"]),
            _insn("0x1001", "MOV", ["[esp + 0x4]", "ebx"]),
            _insn("0x1005", "CALL", ["edx"], is_call=True, is_indirect_call=True),
        ]
        site = analyze_call_sites(records, pointer_size=4)[0]
        assert [(w.slot_offset, w.source) for w in site.stack_args] == [
            (0, "eax"),
            (4, "ebx"),
        ]


class TestWarningsAndConfidence:
    def test_ecx_pushed_raw_triggers_nonstandard_warning(self):
        records = [
            _insn("0x1000", "MOV", ["ecx", "esi"]),
            _insn("0x1002", "PUSH", ["ecx"]),
            _insn("0x1003", "CALL", ["eax"], is_call=True, is_indirect_call=True),
        ]
        site = analyze_call_sites(records, pointer_size=4)[0]
        assert any("non-standard" in w for w in site.warnings)

    def test_indirect_unknown_convention_is_low_confidence(self):
        records = [
            _insn("0x1000", "PUSH", ["eax"]),
            _insn(
                "0x1001",
                "CALL",
                ["dword ptr [0x401000]"],
                is_call=True,
                is_indirect_call=True,
            ),
        ]
        site = analyze_call_sites(records, pointer_size=4)[0]
        assert site.confidence == "low"
        assert any("verify" in w for w in site.warnings)

    def test_cleanup_mismatch_warns(self):
        records = [
            _insn("0x1000", "PUSH", ["eax"]),
            _insn("0x1001", "CALL", ["edx"], is_call=True, is_indirect_call=True),
            _insn("0x1003", "ADD", ["esp", "0x10"]),
        ]
        site = analyze_call_sites(records, pointer_size=4)[0]
        assert site.confidence == "low"
        assert any("does not match" in w for w in site.warnings)


class TestScanBoundaries:
    def test_stops_at_jump_target(self):
        records = [
            _insn("0x1000", "PUSH", ["eax"]),
            _insn("0x1001", "PUSH", ["ebx"]),
            _insn("0x1002", "CALL", ["ecx"], is_call=True, is_indirect_call=True),
        ]
        sites = analyze_call_sites(records, pointer_size=4, jump_targets=frozenset({"0x1001"}))
        site = sites[0]
        # The push at the jump target is still counted; the one above it is not.
        assert [(w.slot_offset, w.source) for w in site.stack_args] == [(0, "ebx")]

    def test_stops_at_previous_call(self):
        records = [
            _insn("0x1000", "PUSH", ["eax"]),
            _insn("0x1001", "CALL", ["edx"], is_call=True, is_indirect_call=True),
            _insn("0x1003", "PUSH", ["ebx"]),
            _insn("0x1004", "CALL", ["ecx"], is_call=True, is_indirect_call=True),
        ]
        sites = analyze_call_sites(records, pointer_size=4)
        assert len(sites) == 2
        # Second call only sees its own push — not the first call's.
        assert [(w.slot_offset, w.source) for w in sites[1].stack_args] == [(0, "ebx")]

    def test_max_scan_truncation_warns(self):
        records = [
            _insn("0x1000", "PUSH", ["ebp"]),
            _insn("0x1001", "NOP", []),
            _insn("0x1002", "NOP", []),
            _insn("0x1003", "PUSH", ["eax"]),
            _insn("0x1004", "CALL", ["edx"], is_call=True, is_indirect_call=True),
        ]
        site = analyze_call_sites(records, pointer_size=4, max_scan=2)[0]
        assert any("truncated" in w for w in site.warnings)


class TestX64:
    def test_register_args_collected(self):
        records = [
            _insn("0x1000", "MOV", ["rcx", "rax"]),
            _insn("0x1003", "MOV", ["rdx", "0x10"]),
            _insn("0x1007", "CALL", ["rax"], is_call=True, is_indirect_call=True),
        ]
        site = analyze_call_sites(records, pointer_size=8)[0]
        assert site.register_args == {"rcx": "rax", "rdx": "0x10"}
        assert site.stack_args == []


# ---------------------------------------------------------------------------
# classify_registers / p-code fallback helpers
# ---------------------------------------------------------------------------

from ghidra_nexus.callsite_analysis import (  # noqa: E402
    CallSiteAnalysis,
    apply_pcode_arg_count,
    classify_registers,
    needs_pcode_fallback,
)


class TestClassifyRegisters:
    def test_saved_vs_clobbered_split(self):
        result = classify_registers(
            written={"ebx", "ecx", "esi"},
            saved={"ebx", "esi"},
            pointer_size=4,
        )
        assert result["saved"] == ["ebx", "esi"]
        assert result["clobbered_volatile"] == ["ecx"]
        assert result["clobbered_non_volatile"] == []

    def test_non_volatile_clobber_is_flagged(self):
        result = classify_registers(written={"edi", "eax"}, saved=set(), pointer_size=4)
        assert result["clobbered_non_volatile"] == ["edi"]
        assert result["clobbered_volatile"] == ["eax"]

    def test_stack_pointer_excluded(self):
        result = classify_registers(written={"esp", "eax"}, saved=set(), pointer_size=4)
        assert result["clobbered_volatile"] == ["eax"]
        assert "esp" not in result["saved"]

    def test_x64_volatility_sets(self):
        result = classify_registers(written={"r8", "r12", "rbx"}, saved={"rbx"}, pointer_size=8)
        assert result["saved"] == ["rbx"]
        assert result["clobbered_volatile"] == ["r8"]
        assert result["clobbered_non_volatile"] == ["r12"]


def _site(**kwargs) -> CallSiteAnalysis:
    defaults = dict(address="0x1000", instruction="CALL EAX", is_indirect=True)
    defaults.update(kwargs)
    return CallSiteAnalysis(**defaults)


class TestPcodeFallback:
    def test_indirect_without_args_needs_fallback(self):
        assert needs_pcode_fallback(_site()) is True

    def test_indirect_with_args_does_not(self):
        from ghidra_nexus.callsite_analysis import StackWriteEvidence

        site = _site(stack_args=[StackWriteEvidence(0, "eax", None, "0x900", "push")])
        assert needs_pcode_fallback(site) is False

    def test_direct_call_never_needs_fallback(self):
        assert needs_pcode_fallback(_site(is_indirect=False)) is False

    def test_truncated_scan_needs_fallback(self):
        from ghidra_nexus.callsite_analysis import StackWriteEvidence

        site = _site(
            stack_args=[StackWriteEvidence(0, "eax", None, "0x900", "push")],
            warnings=["backward scan truncated at max_scan; ..."],
        )
        assert needs_pcode_fallback(site) is True

    def test_apply_matching_count_is_silent(self):
        from ghidra_nexus.callsite_analysis import StackWriteEvidence

        site = _site(stack_args=[StackWriteEvidence(0, "eax", None, "0x900", "push")])
        apply_pcode_arg_count(site, 1)
        assert site.pcode_arg_count == 1
        assert site.warnings == []

    def test_apply_mismatching_count_warns(self):
        from ghidra_nexus.callsite_analysis import StackWriteEvidence

        site = _site(stack_args=[StackWriteEvidence(0, "eax", None, "0x900", "push")])
        apply_pcode_arg_count(site, 3)
        assert site.pcode_arg_count == 3
        assert any("decompiler assumes 3" in w for w in site.warnings)

    def test_apply_with_no_observed_args_warns(self):
        site = _site()
        apply_pcode_arg_count(site, 2)
        assert any("no stack arguments observed" in w for w in site.warnings)
