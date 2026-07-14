"""Unit tests for notebook.addresses (Phase 1 / F5)."""

from __future__ import annotations

import pytest

from ghidra_nexus.notebook.addresses import (
    normalize_hex,
    parse_addr_token,
    to_int,
    to_rva,
    to_va,
)


class TestNormalizeHex:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("0x401000", "0x401000"),
            ("0X401000", "0x401000"),
            ("0x00401000", "0x401000"),
            ("0x0", "0x0"),
            ("0", "0x0"),
            (4198400, "0x401000"),  # int input
            ("  0x401000  ", "0x401000"),  # whitespace
            ("0xDEAD_BEEF", "0xdeadbeef"),
        ],
    )
    def test_normalizes(self, raw, expected):
        assert normalize_hex(raw) == expected

    def test_zero(self):
        assert normalize_hex("0x0") == "0x0"

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            normalize_hex("")

    def test_negative_raises(self):
        with pytest.raises(ValueError):
            normalize_hex("-1")


class TestToInt:
    def test_canonical(self):
        assert to_int("0x401000") == 0x401000

    def test_no_prefix(self):
        assert to_int("401000") == 0x401000

    def test_leading_zeros(self):
        assert to_int("0x00401000") == 0x401000

    def test_uppercase(self):
        assert to_int("0XDEADBEEF") == 0xDEADBEEF

    def test_invalid(self):
        with pytest.raises(ValueError):
            to_int("not_a_number")


class TestToRva:
    def test_va_minus_base(self):
        # Standard PE: image_base 0x140000000, function VA 0x140001000 → RVA 0x1000
        assert to_rva("0x140001000", "0x140000000") == "0x1000"

    def test_exact_base_returns_zero(self):
        # VA == image_base → RVA 0x0
        assert to_rva("0x140000000", "0x140000000") == "0x0"

    def test_int_inputs(self):
        assert to_rva(0x140001000, 0x140000000) == "0x1000"

    def test_no_image_base_raises(self):
        with pytest.raises(ValueError, match="image_base"):
            to_rva("0x140001000", None)

    def test_below_base_raises(self):
        with pytest.raises(ValueError, match="below image_base"):
            to_rva("0x100", "0x140000000")


class TestToVa:
    def test_rva_plus_base(self):
        assert to_va("0x1000", "0x140000000") == "0x140001000"

    def test_int_inputs(self):
        assert to_va(0x1000, 0x140000000) == "0x140001000"

    def test_zero_rva(self):
        assert to_va("0x0", "0x140000000") == "0x140000000"


class TestParseAddrToken:
    """parse_addr_token: handles agent-supplied strings, possibly without
    image_base (we have to make a choice between VA and RVA)."""

    def test_no_image_base_keeps_value(self):
        # No image_base → trust the agent, store as canonical RVA.
        assert parse_addr_token("0x401000", None) == "0x401000"

    def test_below_base_treated_as_rva(self):
        # 0x1000 < 0x140000000 → already an RVA.
        assert parse_addr_token("0x1000", "0x140000000") == "0x1000"

    def test_above_base_treated_as_va(self):
        # 0x140001000 >= 0x140000000 → VA, convert.
        assert parse_addr_token("0x140001000", "0x140000000") == "0x1000"

    def test_exact_base_returns_zero(self):
        assert parse_addr_token("0x140000000", "0x140000000") == "0x0"

    def test_strips_whitespace(self):
        assert parse_addr_token("  0x401000  ", None) == "0x401000"

    def test_bare_hex_with_base(self):
        # 4198400 (= 0x401000) < 0x140000000 → treated as RVA (kept verbatim).
        assert parse_addr_token("401000", "0x140000000") == "0x401000"

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            parse_addr_token("", None)

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="empty"):
            parse_addr_token("   ", None)


class TestRoundTrips:
    """Across-binary safety: same RVA works for different image_bases."""

    def test_same_rva_different_bases(self):
        # Two DLLs both have function at RVA 0x1000.
        rva1 = to_rva("0x140001000", "0x140000000")
        rva2 = to_rva("0x180001000", "0x180000000")
        assert rva1 == rva2 == "0x1000"

        # On retrieval we add the right image_base back.
        assert to_va(rva1, "0x140000000") == "0x140001000"
        assert to_va(rva2, "0x180000000") == "0x180001000"
