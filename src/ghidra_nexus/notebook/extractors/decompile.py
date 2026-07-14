"""Decompile extractor — derives a deterministic view of a decompiled function.

This is the canonical :class:`Extractor` and the first one Phase 1 ships. It runs
on the decompiled C-like pseudo-code and emits:

- **summary** — a one-paragraph function description: name, line count, top callees,
  top APIs, top strings, notable constants.
- **key_entities** — every discovered API call, string literal, immediate constant
  ≥16-bit, callee reference. Values are grounded substrings of the input.
- **quality_hint** — ``stub`` (≤8 bytes / very few lines), ``empty`` (no C output),
  ``encrypted`` (status was error and error_code was set), or ``ok``.

Phase 2 may add caller/callee semantics from the Ghidra function object (passed via
``payload``), but the textual extraction is fully pure-Python and ships now.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from ghidra_nexus.notebook.extractors.base import (
    ExtractedView,
    KeyEntity,
    register,
)

# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------

# API-call-shaped tokens in C pseudo-code: ``Foo(...)`` or ``Foo::method``.
# We only emit an entity when the callee is a *recognised* API name (uppercase
# letter in the first 1–2 chars, length >= 3, no spaces). This is intentionally
# conservative — false positives hurt search more than missed calls.
_API_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]{2,})\s*\(")
# Plain ``"..."`` string literal.
_STRING_RE = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')
# Immediate integer 0xNN where NN >= 0x100 (16-bit) to avoid picking up loop
# counters / small flags.
_IMM16_RE = re.compile(r"0x([0-9a-fA-F]{3,8})\b")
# Callee ref via the address token Ghidra uses in decompiler output:
# ``sub_401000`` or ``LAB_140001000`` or ``DAT_1400...``. We capture the prefix
# and the address separately so the entity value is the full token (e.g.
# ``sub_401000``) but ``rva`` carries the bare address.
_CALLEE_RE = re.compile(r"\b(sub|LAB|DAT|FUN)_(0x[0-9a-fA-F]+|[0-9a-fA-F]+)\b")

# Decompiler-level noise that should never become entities: Ghidra bookkeeping
# macros, intrinsics, casts.
_NOISE_API = frozenset(
    {
        "Func_Call",
        "PTR_",
        "CAST",
        "LABEL",
        "IF",  # control flow keyword — fine to drop from entities
    }
)

# Constants that show up in every function — don't bother emitting.
_TRIVIAL_IMMS = {"0", "1", "0x0", "0x1", "0x100", "0xff"}


_MAX_ENTITIES_PER_KIND = 32
_MAX_SUMMARY_ENTITIES = 8


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------

class DecompileExtractor:
    kind = "decompile"

    def extract(self, payload: dict[str, Any]) -> ExtractedView:
        name: str = payload.get("name") or "<unknown>"
        rva: str | None = payload.get("addr") or payload.get("rva")
        code: str = payload.get("code") or ""
        signature: str | None = payload.get("signature")
        decompiler_status: str = payload.get("decompiler_status") or "decompiled"
        error_code: str | None = payload.get("error_code")
        lines = int(payload.get("lines") or code.count("\n") + (1 if code else 0))

        # Quality hint
        quality = self._quality_hint(code, decompiler_status, lines, error_code)

        # Build entities
        apis = self._extract_apis(code)
        strings = self._extract_strings(code)
        callees = self._extract_callees(code)  # list[(full, addr)]
        imms = self._extract_imms(code)

        entities: list[KeyEntity] = []
        for v in apis[:_MAX_ENTITIES_PER_KIND]:
            entities.append(KeyEntity(kind="api", value=v))
        for v in strings[:_MAX_ENTITIES_PER_KIND]:
            entities.append(KeyEntity(kind="string", value=v))
        for full, addr in callees[:_MAX_ENTITIES_PER_KIND]:
            entities.append(KeyEntity(kind="callee", value=full, rva=addr))
        for v in imms[:_MAX_ENTITIES_PER_KIND]:
            entities.append(KeyEntity(kind="imm", value=f"0x{v}"))

        # Summary uses the full token strings for readability.
        summary = self._build_summary(
            name,
            lines,
            apis,
            strings,
            [full for full, _ in callees],
            signature,
            quality,
        )
        return ExtractedView(
            summary=summary,
            key_entities=entities,
            view_model="extractive_v1",
            quality_hint=quality,
        )

    # ------------------------------------------------------------------
    # Heuristic internals
    # ------------------------------------------------------------------

    @staticmethod
    def _quality_hint(
        code: str, status: str, lines: int, error_code: str | None
    ) -> str:
        if status == "decompiler_error" or (error_code and error_code != "ok"):
            # The error_code from errors.py is one of "encrypted_bytes",
            # "function_too_small", "no_license", "unsupported_isa",
            # "type_error", or "decompile_failed". Surface the most actionable
            # categorization.
            if error_code and "encrypted" in error_code:
                return "encrypted"
            if error_code in {"function_too_small", "no_license"}:
                return "stub"
            return "empty"
        if not code or not code.strip():
            return "empty"
        if lines <= 1:
            return "stub"
        return "ok"

    @staticmethod
    def _extract_apis(code: str) -> list[str]:
        if not code:
            return []
        counts = Counter()
        for m in _API_RE.finditer(code):
            name = m.group(1)
            # Drop known noise / casts / macros.
            if name in _NOISE_API:
                continue
            # Heuristic: an API call is usually 3+ chars starting with uppercase.
            if not name[0].isupper():
                continue
            counts[name] += 1
        # Order by frequency then alphabetical.
        return [n for n, _ in counts.most_common(_MAX_ENTITIES_PER_KIND)]

    @staticmethod
    def _extract_strings(code: str) -> list[str]:
        if not code:
            return []
        seen: set[str] = set()
        for m in _STRING_RE.finditer(code):
            s = m.group(1)
            if not s or len(s) > 200:
                continue
            seen.add(s)
            if len(seen) >= _MAX_ENTITIES_PER_KIND:
                break
        return sorted(seen)

    @staticmethod
    def _extract_callees(code: str) -> list[tuple[str, str | None]]:
        """Yield ``(full_token, address_or_None)`` tuples preserving order."""
        if not code:
            return []
        seen: dict[str, str | None] = {}
        for m in _CALLEE_RE.finditer(code):
            full = m.group(0)              # e.g. "sub_401000"
            addr = m.group(2)              # e.g. "401000"
            if full not in seen:
                # Normalize the address to canonical ``0x`` lowercase form so
                # callers can pattern-match on it.
                try:
                    norm = "0x" + addr.lower().lstrip("0x")
                except Exception:
                    norm = addr
                seen[full] = norm
            if len(seen) >= _MAX_ENTITIES_PER_KIND:
                break
        return [(k, v) for k, v in seen.items()]

    @staticmethod
    def _extract_imms(code: str) -> list[str]:
        if not code:
            return []
        seen: list[str] = []
        for m in _IMM16_RE.finditer(code):
            hex_part = m.group(1).lower()
            if hex_part in _TRIVIAL_IMMS:
                continue
            seen.append(hex_part)
            if len(seen) >= _MAX_ENTITIES_PER_KIND:
                break
        return seen

    @staticmethod
    def _build_summary(
        name: str,
        lines: int,
        apis: list[str],
        strings: list[str],
        callees: list[str],
        signature: str | None,
        quality: str,
    ) -> str:
        """Compose a deterministic one-paragraph summary.

        Target ~80–120 words. Never invent facts: only reference values that
        were extracted from the input.
        """
        if quality == "empty":
            return f"Function {name}: decompilation produced no usable output."
        if quality == "stub":
            return f"Function {name}: stub ({lines} line(s)); skip or disassemble for raw bytes."

        chunks: list[str] = []
        sig = signature or ""
        head = f"Function {name}"
        if sig:
            head += f" — {sig}"
        head += f", {lines} lines."
        chunks.append(head)

        if callees:
            top_callees = ", ".join(_join_tokens(callees, _MAX_SUMMARY_ENTITIES))
            chunks.append(f"Calls {top_callees}.")
        if apis:
            top_apis = ", ".join(_join_tokens(apis, _MAX_SUMMARY_ENTITIES))
            chunks.append(f"Uses APIs {top_apis}.")
        if strings:
            top_strings = ", ".join(_join_tokens(strings, _MAX_SUMMARY_ENTITIES))
            chunks.append(f"String literals: {top_strings}.")
        return " ".join(chunks)


def _join_tokens(items: list[str], n: int) -> list[str]:
    """Take first n items, normalize hex to lowercase ``0x`` form."""
    out: list[str] = []
    for v in items[:n]:
        if v.startswith(("sub_", "LAB_", "DAT_", "FUN_")) and "_" in v:
            # Address-bearing token: keep as-is.
            out.append(v)
        else:
            out.append(v)
    return out


# Self-register on import.
register(DecompileExtractor())
