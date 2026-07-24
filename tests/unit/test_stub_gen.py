"""Unit tests for the pure hook-stub renderer (no JVM required)."""

from __future__ import annotations

from ghidra_nexus.stub_gen import (
    StubArg,
    StubSpec,
    arg_type_from_evidence,
    normalize_convention,
    render_hook_stub,
)


class TestNormalizeConvention:
    def test_strips_inference_marker(self):
        assert normalize_convention("__thiscall?", 4) == "thiscall"

    def test_known_conventions(self):
        assert normalize_convention("__cdecl", 4) == "cdecl"
        assert normalize_convention("__stdcall", 4) == "stdcall"
        assert normalize_convention("__fastcall", 4) == "fastcall"

    def test_vectorcall_maps_to_fastcall(self):
        assert normalize_convention("__vectorcall", 4) == "fastcall"

    def test_empty_defaults_by_pointer_size(self):
        assert normalize_convention(None, 4) == "cdecl"
        assert normalize_convention("", 8) == "win64"

    def test_garbage_is_unknown(self):
        assert normalize_convention("__watcall", 4) == "unknown"


class TestArgTypeFromEvidence:
    def test_address_resolution_means_pointer(self):
        assert arg_type_from_evidence("&[sp+0x24]", "zig", 4) == "*anyopaque"
        assert arg_type_from_evidence("&[sp+0x24]", "c", 4) == "void *"

    def test_plain_values_default_to_word(self):
        assert arg_type_from_evidence(None, "zig", 4) == "u32"
        assert arg_type_from_evidence("[eax]", "c", 8) == "uint64_t"


def _spec(**kwargs) -> StubSpec:
    defaults = dict(
        target_name="sub_887280",
        address="0x8872AC",
        language="zig",
        convention="thiscall",
        convention_label="__thiscall?",
        args=[
            StubArg("this", "*anyopaque", "ecx <- [eax]"),
            StubArg("arg1", "u32", "[sp+0x00] <- eax"),
            StubArg("arg2", "u32", "[sp+0x04] <- edx"),
        ],
    )
    defaults.update(kwargs)
    return StubSpec(**defaults)


class TestZigRender:
    def test_fn_type_and_callconv(self):
        stub = render_hook_stub(_spec())
        assert "pub const sub_887280_fn = *const fn (" in stub
        assert ") callconv(.thiscall) i32;" in stub
        assert "this: *anyopaque, // ecx <- [eax]" in stub
        assert "arg2: u32, // [sp+0x04] <- edx" in stub

    def test_header_warns_to_verify(self):
        stub = render_hook_stub(_spec())
        assert "run verify_port before writing patch bytes" in stub

    def test_clobber_comments(self):
        stub = render_hook_stub(
            _spec(clobbered_non_volatile=["ebx"], clobbered_volatile=["eax"])
        )
        assert "ebx" in stub and "save/restore" in stub
        assert "Volatile clobbers (no save needed): eax" in stub

    def test_reserved_word_arg_is_escaped(self):
        stub = render_hook_stub(
            _spec(args=[StubArg("type", "u32", "")])
        )
        assert "type_: u32," in stub

    def test_cdecl_callconv(self):
        stub = render_hook_stub(_spec(convention="cdecl"))
        assert "callconv(.C)" in stub


class TestCRender:
    def _c_spec(self, **kwargs) -> StubSpec:
        defaults = dict(
            target_name="sub_887280",
            address="0x8872AC",
            language="c",
            convention="stdcall",
            convention_label="__stdcall",
            args=[
                StubArg("this", "void *", "ecx <- [eax]"),
                StubArg("arg1", "uint32_t", "[sp+0x00] <- eax"),
                StubArg("arg2", "uint32_t", "[sp+0x04] <- edx"),
            ],
        )
        defaults.update(kwargs)
        return StubSpec(**defaults)

    def test_typedef_with_qualifier(self):
        stub = render_hook_stub(self._c_spec())
        assert "typedef int (__stdcall *sub_887280_fn)(" in stub
        assert "void * this" in stub
        assert "uint32_t arg1" in stub

    def test_evidence_notes_listed(self):
        stub = render_hook_stub(self._c_spec(convention="thiscall"))
        assert "//   arg2: [sp+0x04] <- edx" in stub

    def test_win64_has_no_qualifier(self):
        stub = render_hook_stub(self._c_spec(convention="win64"))
        assert "typedef int (*sub_887280_fn)(" in stub

    def test_empty_args_emits_void(self):
        stub = render_hook_stub(self._c_spec(args=[]))
        assert "(void);" in stub


class TestUnsupportedLanguage:
    def test_raises(self):
        import pytest

        with pytest.raises(ValueError, match="Unsupported language"):
            render_hook_stub(_spec(language="rust"))
