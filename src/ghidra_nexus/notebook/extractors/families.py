"""Disassembly extractor — deterministic view of a disassembled function.
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

# Mnemonic patterns we care about: call targets, branch targets, mov immediates
_CALL_TARGET_RE = re.compile(r"\b(call|jmp|jn?z|je|jg|jl|jge|jle|ja|jb|jae|jbe)\s+((?:0x[0-9a-fA-F]+)|(?:sub|LAB|DAT|FUN)_[0-9a-fA-Fx]+)", re.IGNORECASE)
_IMM_RE = re.compile(r"(?:mov|add|sub|xor|cmp|and|or|test|lea)\s+[^,]+,\s*(0x[0-9a-fA-F]{3,})", re.IGNORECASE)

_MAX_ENTITIES_PER_KIND = 32


class DisasmExtractor:
    kind = "disasm"

    def extract(self, payload: dict[str, Any]) -> ExtractedView:
        name: str = payload.get("function_name") or payload.get("name") or "<unknown>"
        address: str = payload.get("address") or payload.get("start_ea") or ""
        instruction_count: int = payload.get("count") or payload.get("instruction_count") or 0
        listing: str = payload.get("listing") or ""

        entities: list[KeyEntity] = []
        call_targets = self._extract_targets(listing)
        immediates = self._extract_immediates(listing)

        for v in call_targets[:_MAX_ENTITIES_PER_KIND]:
            entities.append(KeyEntity(kind="callee", value=v))
        for v in immediates[:_MAX_ENTITIES_PER_KIND]:
            # Normalize hex
            try:
                norm = f"0x{int(v, 16):x}"
            except Exception:
                norm = v
            entities.append(KeyEntity(kind="imm", value=norm))

        summary = self._build_summary(name, address, instruction_count, call_targets)

        return ExtractedView(
            summary=summary,
            key_entities=entities,
            view_model="extractive_v1",
            quality_hint="ok" if instruction_count > 0 else "empty",
        )

    @staticmethod
    def _extract_targets(listing: str) -> list[str]:
        if not listing:
            return []
        seen: list[str] = []
        for m in _CALL_TARGET_RE.finditer(listing):
            target = m.group(2)
            if target not in seen:
                seen.append(target)
            if len(seen) >= _MAX_ENTITIES_PER_KIND:
                break
        return seen

    @staticmethod
    def _extract_immediates(listing: str) -> list[str]:
        if not listing:
            return []
        seen: list[str] = []
        for m in _IMM_RE.finditer(listing):
            val = m.group(1)
            if val not in seen and val not in ("0x0", "0x1", "0xff"):
                seen.append(val)
            if len(seen) >= _MAX_ENTITIES_PER_KIND:
                break
        return seen

    @staticmethod
    def _build_summary(
        name: str,
        address: str,
        instruction_count: int,
        call_targets: list[str],
    ) -> str:
        if not address:
            return f"Disassembly of {name}: {instruction_count} instructions."
        top = ", ".join(call_targets[:8])
        parts = [f"Disassembly of {name} at {address}: {instruction_count} instructions."]
        if call_targets:
            parts.append(f"Targets: {top}.")
        return " ".join(parts)


register(DisasmExtractor())


# ---------------------------------------------------------------------------
# Xrefs extractor
# ---------------------------------------------------------------------------

class XrefsExtractor:
    kind = "xrefs"

    def extract(self, payload: dict[str, Any]) -> ExtractedView:
        target: str = payload.get("target") or ""
        xrefs: list = payload.get("cross_references") or []
        total = len(xrefs)

        entities: list[KeyEntity] = []
        functions: set[str] = set()
        xref_types = Counter()
        for x in xrefs:
            fn = x.get("function_name")
            if fn:
                functions.add(fn)
                if len(entities) < _MAX_ENTITIES_PER_KIND:
                    entities.append(KeyEntity(kind="callee", value=fn))
            xref_types[x.get("type", "unknown")] += 1

        type_str = ", ".join(f"{t}x{c}" for t, c in xref_types.most_common(6))
        summary = f"{total} cross-references to {target}. Types: {type_str}."
        if functions:
            summary += f" Functions: {', '.join(sorted(functions)[:10])}."

        return ExtractedView(
            summary=summary,
            key_entities=entities,
            view_model="extractive_v1",
            quality_hint="ok" if total > 0 else "empty",
        )


register(XrefsExtractor())


# ---------------------------------------------------------------------------
# Strings extractor — trivial but provides entities for FTS
# ---------------------------------------------------------------------------

class StringsExtractor:
    kind = "strings"

    def extract(self, payload: dict[str, Any]) -> ExtractedView:
        strings: list = payload.get("strings") or []
        total = len(strings)
        top = strings[:20]
        entities = [
            KeyEntity(kind="string", value=s.get("value", ""))
            for s in top
            if s.get("value")
        ]
        joined = ", ".join(f'"{s.get("value", "")}"' for s in top[:8])
        summary = f"{total} strings found. Top: {joined}." if strings else "No strings found."
        return ExtractedView(
            summary=summary,
            key_entities=entities,
            view_model="extractive_v1",
            quality_hint="ok" if total > 0 else "empty",
        )


register(StringsExtractor())


# ---------------------------------------------------------------------------
# Section health extractor
# ---------------------------------------------------------------------------

class SectionHealthExtractor:
    kind = "section_health"

    def extract(self, payload: dict[str, Any]) -> ExtractedView:
        # payload is list[SectionHealth] or dict with results
        results = payload if isinstance(payload, list) else payload.get("results", [])
        high_entropy: list[str] = []
        entities: list[KeyEntity] = []
        for s in results:
            name = s.get("name", "")
            cls = s.get("classification", "")
            rec = s.get("recommendation", "")
            if cls in ("encrypted", "compressed"):
                high_entropy.append(f"{name}({cls}:{rec})")
                entities.append(KeyEntity(kind="section", value=name))

        summary = f"Section health: {len(results)} sections assessed."
        if high_entropy:
            summary += f" High-entropy: {', '.join(high_entropy[:6])}."
        return ExtractedView(
            summary=summary,
            key_entities=entities,
            view_model="extractive_v1",
            quality_hint="ok",
        )


register(SectionHealthExtractor())
