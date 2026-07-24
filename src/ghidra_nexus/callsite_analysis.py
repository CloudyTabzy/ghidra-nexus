"""Pure-Python call-site stack analysis (no Ghidra/JVM imports).

Consumes linearized instruction records for one function body and reconstructs,
for every ``CALL``, the stack-argument evidence (``PUSH`` / ``MOV [sp+X]`` writes)
plus a calling-convention inference with an explicit confidence level.

This module exists so the heuristic core is unit-testable without a JVM.
``GhidraTools.analyze_call_sites`` builds the :class:`InsnRecord` list from real
listing instructions; everything below is plain Python.

Offset convention: ``slot_offset`` is expressed in the **call-time SP frame** —
the first stack argument (the value the callee reads as ``[esp+4]`` on x86-32
after the return-address push) has ``slot_offset == 0``. Memory expressions in
resolved sources are normalized into the same frame (``[sp+0xNN]``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Input records
# ---------------------------------------------------------------------------

# General-purpose registers we track for one-level def resolution.
_GP_REGS = frozenset(
    {
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp",
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "ax", "bx", "cx", "dx", "si", "di", "al", "bl", "cl", "dl",
    }
)

_SP_NAMES = frozenset({"esp", "rsp", "sp"})

# Instructions that rebuild SP outright; the frame is lost past them.
_SP_REBUILDING_MNEMONICS = frozenset({"mov", "xchg", "leave", "enter", "pop"})

_MOV_MNEMONICS = frozenset({"mov", "movzx", "movsx"})

# x64 integer argument registers (Microsoft x64 ABI), in order.
_X64_ARG_REGS = ("rcx", "rdx", "r8", "r9")

# x86-32 register that carries `this` under __thiscall.
_X86_THIS_REG = "ecx"

# Mnemonics whose first operand is read, never written — must not kill a
# tracked register def when seen as ``op0``.
_NON_WRITING_MNEMONICS = frozenset(
    {
        "cmp", "test", "nop", "jmp", "call", "ret", "retn", "retf", "push",
        "leave", "enter", "int", "syscall",
        "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge",
        "jl", "jle", "jo", "jno", "js", "jns", "jp", "jnp", "jcxz", "jecxz",
        "jrcxz", "loop", "loope", "loopne",
    }
)

_IMM_RE = re.compile(r"^(?:-?0x[0-9a-fA-F]+|-?\d+|[0-9a-fA-F]+h)$")
_SP_MEM_RE = re.compile(
    r"^\[\s*(?P<sp>esp|rsp|sp)\s*(?:\+\s*(?P<off>0x[0-9a-fA-F]+|\d+|[0-9a-fA-F]+h))?\s*\]$",
    re.IGNORECASE,
)


def _parse_imm(text: str) -> int | None:
    """Parse an immediate operand (``0x10``, ``10h``, ``16``) to int."""
    t = text.strip().lower()
    if not _IMM_RE.match(t):
        return None
    try:
        if t.endswith("h"):
            return int(t[:-1], 16)
        return int(t, 0)
    except ValueError:
        return None


def _is_register(text: str) -> bool:
    return text.strip().lower() in _GP_REGS


def _match_sp_mem(text: str) -> int | None:
    """If ``text`` is an SP-relative memory operand (``[esp+0x14]``), return X."""
    m = _SP_MEM_RE.match(text.strip())
    if m is None:
        return None
    off = m.group("off")
    if off is None:
        return 0
    return _parse_imm(off)


@dataclass
class InsnRecord:
    """One listing instruction, linearized for the analyzer."""

    address: str
    mnemonic: str
    operands: list[str]
    is_call: bool = False
    is_ret: bool = False
    is_unconditional_jump: bool = False
    is_indirect_call: bool = False
    # Direct-call target facts, filled by the Ghidra side when resolvable.
    target_name: str | None = None
    target_address: str | None = None
    callee_convention: str | None = None
    callee_param_count: int | None = None

    def text(self) -> str:
        ops = ",".join(self.operands)
        return f"{self.mnemonic} {ops}".strip()


# ---------------------------------------------------------------------------
# Output records
# ---------------------------------------------------------------------------

@dataclass
class StackWriteEvidence:
    """One observed stack write feeding a call."""

    slot_offset: int  # bytes in the call-time SP frame; first stack arg = 0
    source: str  # raw source operand text
    resolved_source: str | None  # one-level register def, normalized to call-time frame
    written_at: str  # address of the PUSH/MOV instruction
    write_kind: str  # "push" | "mov"

    def to_dict(self) -> dict:
        return {
            "slot_offset": self.slot_offset,
            "source": self.source,
            "resolved_source": self.resolved_source,
            "written_at": self.written_at,
            "write_kind": self.write_kind,
        }


@dataclass
class CallSiteAnalysis:
    """Reconstructed evidence for a single CALL instruction."""

    address: str
    instruction: str
    is_indirect: bool
    target_name: str | None = None
    target_address: str | None = None
    callee_convention: str | None = None
    callee_param_count: int | None = None
    stack_args: list[StackWriteEvidence] = field(default_factory=list)
    other_stack_writes: list[StackWriteEvidence] = field(default_factory=list)
    register_args: dict[str, str] = field(default_factory=dict)
    ecx_source: str | None = None
    caller_cleanup_bytes: int | None = None
    inferred_convention: str | None = None
    confidence: str = "low"  # "high" | "medium" | "low"
    pcode_arg_count: int | None = None  # cross-check from decompiler P-code
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "instruction": self.instruction,
            "is_indirect": self.is_indirect,
            "target_name": self.target_name,
            "target_address": self.target_address,
            "callee_convention": self.callee_convention,
            "callee_param_count": self.callee_param_count,
            "stack_args": [w.to_dict() for w in self.stack_args],
            "other_stack_writes": [w.to_dict() for w in self.other_stack_writes],
            "register_args": dict(self.register_args),
            "ecx_source": self.ecx_source,
            "caller_cleanup_bytes": self.caller_cleanup_bytes,
            "inferred_convention": self.inferred_convention,
            "confidence": self.confidence,
            "pcode_arg_count": self.pcode_arg_count,
            "warnings": list(self.warnings),
        }


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

def _normalize_mem_expr(expr: str, delta: int) -> str:
    """Normalize an SP-relative memory expression into the call-time frame."""
    off = _match_sp_mem(expr)
    if off is None:
        return expr
    return f"[sp+0x{off + delta:x}]"


def analyze_call_sites(
    records: list[InsnRecord],
    *,
    pointer_size: int = 4,
    max_scan: int = 40,
    jump_targets: frozenset[str] | None = None,
) -> list[CallSiteAnalysis]:
    """Analyze every CALL in ``records`` and return per-site evidence.

    ``jump_targets`` holds addresses inside the function that are branch
    destinations; the backward scan stops after crossing one (the path that
    reached it is unknown, so earlier evidence is unreliable).
    """
    targets = jump_targets or frozenset()
    sites: list[CallSiteAnalysis] = []

    for i, rec in enumerate(records):
        if not rec.is_call:
            continue
        site = CallSiteAnalysis(
            address=rec.address,
            instruction=rec.text(),
            is_indirect=rec.is_indirect_call,
            target_name=rec.target_name,
            target_address=rec.target_address,
            callee_convention=rec.callee_convention,
            callee_param_count=rec.callee_param_count,
        )
        _scan_stack_evidence(records, i, site, pointer_size, max_scan, targets)
        _scan_caller_cleanup(records, i, site)
        _infer_convention(site, pointer_size)
        sites.append(site)

    return sites


# ---------------------------------------------------------------------------
# Backward stack-evidence scan
# ---------------------------------------------------------------------------

@dataclass
class _ScanState:
    """Mutable state for the backward scan of one call site."""

    ptr: int
    writes: dict[int, StackWriteEvidence] = field(default_factory=dict)
    pending: dict[str, list[StackWriteEvidence]] = field(default_factory=dict)
    reg_arg_sources: dict[str, str] = field(default_factory=dict)
    ecx_source: str | None = None
    delta: int = 0  # bytes SP at the scan point sits above the call-time SP


def _note_use(state: _ScanState, evidence: StackWriteEvidence) -> None:
    src = evidence.source.strip().lower()
    if _is_register(src):
        state.pending.setdefault(src, []).append(evidence)


def _resolve_reg_write(state: _ScanState, reg: str, def_text: str | None) -> None:
    """Record a write to ``reg``; resolve pending uses scanned earlier.

    Scanning backwards, the first write to a register we meet is the def that
    was live at every use we already passed (all forward of the write).
    """
    uses = state.pending.pop(reg, [])
    if def_text is not None:
        for evidence in uses:
            evidence.resolved_source = def_text
    if state.ecx_source is None and reg in (_X86_THIS_REG, "rcx") and state.ptr == 4:
        state.ecx_source = def_text
    if state.ptr == 8 and reg in _X64_ARG_REGS and reg not in state.reg_arg_sources:
        state.reg_arg_sources[reg] = def_text or "?"


def _handle_push(state: _ScanState, insn: InsnRecord, ops: list[str]) -> None:
    if not ops:
        return
    ev = StackWriteEvidence(
        slot_offset=state.delta,
        source=ops[0],
        resolved_source=None,
        written_at=insn.address,
        write_kind="push",
    )
    state.writes.setdefault(state.delta, ev)
    _note_use(state, ev)
    state.delta += state.ptr


def _handle_pop(state: _ScanState, insn: InsnRecord, ops: list[str]) -> None:
    if not ops:
        return
    op0 = ops[0].lower()
    if _is_register(op0):
        _resolve_reg_write(state, op0, f"[sp+0x{state.delta:x}]")
    state.delta -= state.ptr


def _handle_mov(state: _ScanState, insn: InsnRecord, ops: list[str]) -> None:
    if len(ops) < 2:
        return
    op0 = ops[0].lower()
    slot_off = _match_sp_mem(ops[0])
    if slot_off is not None:
        ev = StackWriteEvidence(
            slot_offset=state.delta + slot_off,
            source=ops[1],
            resolved_source=None,
            written_at=insn.address,
            write_kind="mov",
        )
        state.writes.setdefault(ev.slot_offset, ev)
        _note_use(state, ev)
        return
    if _is_register(op0):
        _resolve_reg_write(state, op0, _normalize_mem_expr(ops[1], state.delta))


def _handle_lea(state: _ScanState, insn: InsnRecord, ops: list[str]) -> None:
    if len(ops) < 2:
        return
    op0 = ops[0].lower()
    if _is_register(op0):
        _resolve_reg_write(state, op0, f"&{_normalize_mem_expr(ops[1], state.delta)}")


_SCAN_HANDLERS = {
    "push": _handle_push,
    "pop": _handle_pop,
    "mov": _handle_mov,
    "movzx": _handle_mov,
    "movsx": _handle_mov,
    "lea": _handle_lea,
}


def _handle_sp_arith(state: _ScanState, mnem: str, ops: list[str]) -> bool:
    """Apply ``add/sub sp, N`` to the scan delta. Returns True when handled."""
    op0 = ops[0].lower() if ops else ""
    if op0 not in _SP_NAMES or len(ops) < 2:
        return False
    imm = _parse_imm(ops[1])
    if imm is None:
        return True
    state.delta += imm if mnem == "sub" else -imm
    return True


def _kills_def(mnem: str, op0: str) -> bool:
    return (
        _is_register(op0)
        and mnem not in _NON_WRITING_MNEMONICS
        and not mnem.startswith("j")
    )


def _rebuilds_stack(mnem: str, op0: str) -> bool:
    return op0 in _SP_NAMES and mnem in _SP_REBUILDING_MNEMONICS


def _step_scan(state: _ScanState, insn: InsnRecord) -> bool:
    """Fold one instruction into the scan state. Returns False to halt."""
    mnem = insn.mnemonic.strip().lower()
    ops = [o.strip() for o in insn.operands]
    op0 = ops[0].lower() if ops else ""
    if _rebuilds_stack(mnem, op0):
        return False
    handler = _SCAN_HANDLERS.get(mnem)
    if handler is not None:
        handler(state, insn, ops)
        return True
    if mnem in ("sub", "add") and _handle_sp_arith(state, mnem, ops):
        return True
    if _kills_def(mnem, op0):
        _resolve_reg_write(state, op0, None)
    return True


def _scan_stack_evidence(
    records: list[InsnRecord],
    call_index: int,
    site: CallSiteAnalysis,
    ptr: int,
    max_scan: int,
    jump_targets: frozenset[str],
) -> None:
    """Backward scan from the call, reconstructing stack writes.

    ``delta`` tracks how many bytes SP at the current scan point sits *above*
    the call-time SP. A ``PUSH`` crossed at depth ``delta`` wrote slot
    ``delta``; a ``MOV [sp+X]`` crossed at depth ``delta`` wrote slot
    ``delta + X``.
    """
    state = _ScanState(ptr=ptr)
    scanned = 0
    j = call_index - 1
    while j >= 0 and scanned < max_scan:
        insn = records[j]
        if insn.is_call or insn.is_ret or insn.is_unconditional_jump:
            break
        if not _step_scan(state, insn):
            break
        scanned += 1
        if insn.address in jump_targets:
            break
        j -= 1

    _finish_scan(state, site, truncated=(scanned >= max_scan and j >= 0))


def _finish_scan(state: _ScanState, site: CallSiteAnalysis, *, truncated: bool) -> None:
    """Split observed writes into args vs other traffic; attach warnings."""
    ordered = sorted(state.writes.values(), key=lambda w: w.slot_offset)
    args: list[StackWriteEvidence] = []
    others: list[StackWriteEvidence] = []
    expected = 0
    for w in ordered:
        if w.slot_offset == expected and not others:
            args.append(w)
            expected += state.ptr
        else:
            others.append(w)
    site.stack_args = args
    site.other_stack_writes = others
    site.register_args = state.reg_arg_sources if state.ptr == 8 else {}
    site.ecx_source = state.ecx_source

    if truncated and (args or others):
        site.warnings.append(
            "backward scan truncated at max_scan; "
            "stack-arg evidence may be incomplete"
        )
    if others and args:
        site.warnings.append(
            "non-contiguous stack writes observed above the argument region "
            "(locals/spills or missed slots); see other_stack_writes"
        )


# ---------------------------------------------------------------------------
# Caller-cleanup evidence (forward of the call)
# ---------------------------------------------------------------------------

def _scan_caller_cleanup(
    records: list[InsnRecord],
    call_index: int,
    site: CallSiteAnalysis,
) -> None:
    """Look just past the call for ``ADD sp, N`` caller-cleanup evidence.

    Skips benign instructions that often sit between the call and the
    cleanup (return-value stores, compares); stops at anything that
    reshapes the stack or transfers control.
    """
    for k in range(call_index + 1, min(call_index + 4, len(records))):
        insn = records[k]
        if insn.is_call or insn.is_ret or insn.is_unconditional_jump:
            return
        mnem = insn.mnemonic.strip().lower()
        ops = [o.strip() for o in insn.operands]
        op0 = ops[0].lower() if ops else ""
        if mnem == "add" and op0 in _SP_NAMES and len(ops) > 1:
            imm = _parse_imm(ops[1])
            if imm is not None:
                site.caller_cleanup_bytes = imm
            return
        if mnem in ("push", "pop") or (mnem == "sub" and op0 in _SP_NAMES):
            return


# ---------------------------------------------------------------------------
# Convention inference
# ---------------------------------------------------------------------------

def _infer_convention(site: CallSiteAnalysis, ptr: int) -> None:
    """Assign inferred_convention + confidence + warnings from the evidence."""
    # A raw ECX push means `this` travels both in a register and on the
    # stack — the exact non-standard pattern from the field report.
    if any(w.source.strip().lower() in (_X86_THIS_REG, "rcx") for w in site.stack_args):
        site.warnings.append(
            "ECX is both written before the call and pushed as a stack "
            "argument — non-standard pattern; verify argument order manually "
            "before porting"
        )

    if site.callee_convention or site.callee_param_count is not None:
        _infer_from_callee(site)
    else:
        _infer_indirect(site, ptr)

    if site.is_indirect and site.confidence == "low":
        site.warnings.append(
            "indirect call with low-confidence evidence — disassemble the "
            "call site and verify the push order manually before porting"
        )


def _infer_from_callee(site: CallSiteAnalysis) -> None:
    """Direct call with a resolvable callee: trust Ghidra's declaration,
    but cross-check the observed stack-arg count."""
    site.inferred_convention = site.callee_convention
    declared = site.callee_param_count
    if declared is None:
        site.confidence = "medium"
        return
    expected_stack = declared
    conv = (site.callee_convention or "").lower()
    if "thiscall" in conv:
        expected_stack = max(0, declared - 1)
    elif "fastcall" in conv:
        expected_stack = max(0, declared - 2)
    if len(site.stack_args) == expected_stack:
        site.confidence = "high"
    else:
        site.confidence = "medium"
        site.warnings.append(
            f"observed {len(site.stack_args)} stack arg(s) but callee declares "
            f"{declared} parameter(s) ({site.callee_convention or 'unknown'})"
        )


def _infer_indirect(site: CallSiteAnalysis, ptr: int) -> None:
    """Indirect or unresolved target: evidence-based guess."""
    cleanup = site.caller_cleanup_bytes
    if cleanup is not None:
        _infer_with_cleanup(site, cleanup, ptr)
        return

    # No caller cleanup → callee-cleanup convention (or unknown).
    if ptr == 4 and site.ecx_source is not None:
        site.inferred_convention = "__thiscall?"
        site.confidence = "medium"
    elif len(site.stack_args) > 0:
        site.inferred_convention = "__stdcall?"
        site.confidence = "low"
        site.warnings.append(
            "no caller cleanup and no ECX evidence; convention is a guess — "
            "check the callee's epilogue (ret N) before porting"
        )
    elif ptr == 8:
        site.inferred_convention = "__fastcall?"  # MS x64 default
        site.confidence = "low"
    else:
        site.confidence = "low"


def _infer_with_cleanup(site: CallSiteAnalysis, cleanup: int, ptr: int) -> None:
    n_args = len(site.stack_args)
    if n_args * ptr == cleanup:
        site.inferred_convention = "__cdecl?"
        site.confidence = "medium"
    elif n_args > 0 and (n_args - 1) * ptr == cleanup:
        site.inferred_convention = "__fastcall?"
        site.confidence = "low"
        site.warnings.append(
            f"caller cleans up {cleanup} byte(s) but {n_args} stack arg(s) "
            "were observed; one argument may travel in a register"
        )
    else:
        site.inferred_convention = None
        site.confidence = "low"
        site.warnings.append(
            f"caller cleanup of {cleanup} byte(s) does not match "
            f"{n_args} observed stack arg(s) — verify manually before porting"
        )


# ---------------------------------------------------------------------------
# Register-clobber classification (verify_port mitigation)
# ---------------------------------------------------------------------------

# Registers every caller already expects to lose across a call (MS ABI).
_VOLATILE_32 = frozenset({"eax", "ecx", "edx"})
_VOLATILE_64 = frozenset({"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"})

# Registers the ABI says a callee must preserve — a hook breaks if it
# trashes these without saving them.
_NON_VOLATILE_32 = frozenset({"ebx", "esi", "edi", "ebp"})
_NON_VOLATILE_64 = frozenset({"rbx", "rsi", "rdi", "rbp", "r12", "r13", "r14", "r15"})


def classify_registers(
    written: set[str], saved: set[str], pointer_size: int
) -> dict[str, list[str]]:
    """Bucket registers a function writes into saved / clobbered lists.

    ``written`` and ``saved`` hold base register names (lowercase). The stack
    pointer is excluded. Returns ``saved`` (written but restored),
    ``clobbered_volatile`` (clobbered but caller expects it), and
    ``clobbered_non_volatile`` (clobbered ABI-preserved registers — the
    dangerous set for hook authors).
    """
    volatile = _VOLATILE_64 if pointer_size == 8 else _VOLATILE_32
    non_volatile = _NON_VOLATILE_64 if pointer_size == 8 else _NON_VOLATILE_32
    clean = {r for r in written if r not in _SP_NAMES}
    restored = clean & saved
    clobbered = clean - restored
    return {
        "saved": sorted(restored),
        "clobbered_volatile": sorted(clobbered & volatile),
        "clobbered_non_volatile": sorted(clobbered & non_volatile),
    }


# ---------------------------------------------------------------------------
# P-code fallback (cross-check, never an override)
# ---------------------------------------------------------------------------

def needs_pcode_fallback(site: CallSiteAnalysis) -> bool:
    """True when listing-level evidence is too thin to trust alone.

    Triggered for indirect calls with no observed stack/register arguments,
    or when the backward scan was truncated (evidence incomplete). Direct
    calls with a resolved callee never need it — Ghidra's declaration is
    already surfaced.
    """
    if not site.is_indirect:
        return False
    no_args = not site.stack_args and not site.register_args
    truncated = any("truncated" in w for w in site.warnings)
    return no_args or truncated


def apply_pcode_arg_count(site: CallSiteAnalysis, pcode_arg_count: int) -> None:
    """Attach the decompiler's assumed argument count as a cross-check.

    P-code argument counts reflect Ghidra's *assumed* prototype, which may be
    exactly what's wrong (the decompiler flattening problem). They are a
    cross-check only: a disagreement with the listing evidence is itself the
    valuable signal, so it raises a warning rather than overriding anything.
    """
    site.pcode_arg_count = pcode_arg_count
    observed = len(site.stack_args) or None
    if observed is not None and observed != pcode_arg_count:
        site.warnings.append(
            f"decompiler assumes {pcode_arg_count} argument(s) but stack "
            f"evidence shows {observed} — trust the stack evidence and "
            "verify manually before porting"
        )
    elif observed is None:
        site.warnings.append(
            f"no stack arguments observed; decompiler assumes "
            f"{pcode_arg_count} argument(s) — cross-check by hand"
        )
