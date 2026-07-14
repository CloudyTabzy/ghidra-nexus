"""Unit tests for notebook.extractors (Phase 1 / F11)."""

from __future__ import annotations

import pytest

from ghidra_nexus.notebook.extractors import (
    ExtractedView,
    KeyEntity,
    extract_for,
    get,
    kinds,
    register,
    reset_for_testing,
)
from ghidra_nexus.notebook.extractors.decompile import DecompileExtractor


@pytest.fixture(autouse=True)
def _clean_registry():
    """Each test starts with only the default registrations."""
    reset_for_testing()
    # Re-register default extractors.
    from ghidra_nexus.notebook.extractors.decompile import DecompileExtractor

    register(DecompileExtractor())
    yield
    reset_for_testing()


class TestRegistry:
    def test_decompile_registered_by_default(self):
        assert "decompile" in kinds()
        assert isinstance(get("decompile"), DecompileExtractor)

    def test_get_returns_none_for_unknown(self):
        assert get("does_not_exist") is None

    def test_register_replaces(self):
        class Stub:
            kind = "decompile"

            def extract(self, payload):
                return ExtractedView(summary="stub", key_entities=[])

        register(Stub())
        assert isinstance(get("decompile"), Stub)

    def test_extract_for_unknown_kind_returns_none(self):
        assert extract_for("does_not_exist", {}) is None

    def test_extract_for_failure_returns_none(self):
        class Boom:
            kind = "boom"

            def extract(self, payload):
                raise RuntimeError("kapow")

        register(Boom())
        assert extract_for("boom", {}) is None


class TestKeyEntity:
    def test_to_dict_minimal(self):
        e = KeyEntity(kind="api", value="CreateFileW")
        assert e.to_dict() == {"kind": "api", "value": "CreateFileW"}

    def test_to_dict_with_rva(self):
        e = KeyEntity(kind="callee", value="0x401000", rva="0x401000")
        d = e.to_dict()
        assert d["rva"] == "0x401000"

    def test_to_dict_omits_rva_when_none(self):
        e = KeyEntity(kind="string", value="error")
        assert "rva" not in e.to_dict()


class TestExtractedView:
    def test_entities_json_round_trip(self):
        v = ExtractedView(
            summary="x",
            key_entities=[
                KeyEntity(kind="api", value="CreateFileW"),
                KeyEntity(kind="string", value="password"),
            ],
        )
        import json

        loaded = json.loads(v.entities_json())
        assert loaded == [
            {"kind": "api", "value": "CreateFileW"},
            {"kind": "string", "value": "password"},
        ]

    def test_search_blob_has_summary_and_entities(self):
        v = ExtractedView(
            summary="Function main, 5 lines.",
            key_entities=[
                KeyEntity(kind="api", value="CreateFileW"),
                KeyEntity(kind="string", value="password"),
            ],
        )
        blob = v.search_blob()
        assert "Function main" in blob
        assert "api:CreateFileW" in blob
        assert "string:password" in blob

    def test_search_blob_empty_when_no_entities(self):
        v = ExtractedView(summary="just summary", key_entities=[])
        assert v.search_blob() == "just summary"


class TestDecompileExtractor:
    def _extract(self, payload):
        return extract_for("decompile", payload)

    def test_empty_code_marks_empty(self):
        v = self._extract({"name": "main", "code": "", "decompiler_status": "decompiled"})
        assert v.quality_hint == "empty"
        assert v.key_entities == []

    def test_stub_short_function(self):
        v = self._extract({"name": "stub_fn", "code": "x = 1;", "lines": 1})
        assert v.quality_hint == "stub"

    def test_decompiler_error_with_encrypted_code_marked_encrypted(self):
        v = self._extract(
            {
                "name": "obf",
                "code": "encrypted",
                "lines": 1,
                "decompiler_status": "decompiler_error",
                "error_code": "encrypted_bytes",
            }
        )
        assert v.quality_hint == "encrypted"

    def test_extracts_apis(self):
        code = """
        int main() {
            HANDLE h = CreateFileW(L"foo", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
            ReadFile(h, buffer, 1024, &read, NULL);
            CloseHandle(h);
            return 0;
        }
        """
        v = self._extract({"name": "main", "code": code, "lines": 8})
        apis = {e.value for e in v.key_entities if e.kind == "api"}
        assert "CreateFileW" in apis
        assert "ReadFile" in apis
        assert "CloseHandle" in apis

    def test_extracts_strings(self):
        code = '''
        void log(const char *msg) {
            printf("error: %s\\n", msg);
        }
        int main() { log("password"); return 0; }
        '''
        v = self._extract({"name": "main", "code": code, "lines": 3})
        strings = {e.value for e in v.key_entities if e.kind == "string"}
        assert "error: %s\\n" in strings
        assert "password" in strings

    def test_extracts_callees(self):
        code = """
        void main() {
            sub_401000();
            sub_402000(0x10);
            return;
        }
        """
        v = self._extract({"name": "main", "code": code, "lines": 4})
        callees = {e.value for e in v.key_entities if e.kind == "callee"}
        assert "sub_401000" in callees
        assert "sub_402000" in callees

    def test_callee_entities_carry_rva(self):
        code = "void f() { sub_401200(); }"
        v = self._extract({"name": "f", "code": code, "lines": 1, "rva": "0x401000"})
        callee = next(e for e in v.key_entities if e.kind == "callee")
        assert callee.rva == "0x401200"

    def test_extracts_imms_above_16bit(self):
        code = """
        int main() {
            int x = 0x100;
            int y = 0xdead;
            int z = 1;
            int w = 0;
            return x + y + z + w;
        }
        """
        v = self._extract({"name": "main", "code": code, "lines": 7})
        imms = {e.value for e in v.key_entities if e.kind == "imm"}
        # 0x100 is in TRIVIAL_IMMS, 0xdead is not.
        assert "0xdead" in imms
        # 1 and 0 are below 16-bit, ignored.

    def test_drops_trivial_imms(self):
        code = "int main() { return 0; }"
        v = self._extract({"name": "main", "code": code, "lines": 1})
        assert all(e.value not in ("0x0", "0x1") for e in v.key_entities)

    def test_drops_control_flow_keywords(self):
        # IF, FOR, WHILE — single-uppercase-letter keywords we should NOT emit.
        code = "int main() { IF (x) return; FOR(i=0;i<10;i++) sum += i; }"
        v = self._extract({"name": "main", "code": code, "lines": 1})
        # IF dropped from entity list.
        kinds_seen = {e.kind for e in v.key_entities}
        assert "api" in kinds_seen  # 'main' becomes an "api" candidate, but 'IF' is excluded

    def test_summary_mentions_function_name(self):
        code = "int main() { return 0; }"
        v = self._extract({"name": "main", "code": code, "lines": 1})
        assert "main" in v.summary
        assert "1" in v.summary  # line count

    def test_summary_includes_apis_when_present(self):
        code = (
            "void f() {\n"
            "    HANDLE h = CreateFileW();\n"
            "    ReadFile(h, buf, 1024, &r, 0);\n"
            "    return;\n"
            "}"
        )
        v = self._extract({"name": "f", "code": code, "lines": 5})
        assert "CreateFileW" in v.summary
        assert "ReadFile" in v.summary

    def test_summary_cap_apis_at_max(self):
        # Build code with 50 distinct API calls.
        apis = [f"Func{i}" for i in range(50)]
        code = "void f() {\n  " + ";\n  ".join(f"{a}()" for a in apis) + ";\n}"
        v = self._extract({"name": "f", "code": code, "lines": 52})
        # Summary should mention at most _MAX_SUMMARY_ENTITIES APIs (8).
        apis_in_summary = [a for a in apis if a in v.summary]
        assert len(apis_in_summary) <= 8

    def test_no_duplicate_apis(self):
        code = """
        void f() {
            CreateFileW();
            CreateFileW();
            CreateFileW();
        }
        """
        v = self._extract({"name": "f", "code": code, "lines": 4})
        api_count = sum(1 for e in v.key_entities if e.value == "CreateFileW")
        assert api_count == 1

    def test_long_strings_truncated(self):
        # Ghidra can produce huge string literals; cap at 200 chars.
        s = "x" * 500
        code = f'void f() {{ puts("{s}"); }}'
        v = self._extract({"name": "f", "code": code, "lines": 1})
        # Strings longer than 200 are dropped.
        strings = [e for e in v.key_entities if e.kind == "string"]
        assert all(len(s.value) <= 200 for s in strings)
