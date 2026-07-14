"""Address normalization helpers — F5: address identity is ``(binary_id, rva)``.

All notebook tables store ``rva`` (relative virtual address), never VA. Conversions
between VA and RVA happen at the boundary: the agent gives us a VA string from Ghidra,
we subtract the image base, we store RVA; on retrieval we add the image base back if
the caller wants the in-memory pointer.

**Why this is F5:** multi-binary projects (Affinity, GameAssembly) ship 10+ DLLs
with different image bases. Storing VAs would silently collide across binaries when
two functions happen to share an in-memory address but live at different file offsets.
RVA is the only identity that's safe across ASLR and per-binary rebasing.
"""

from __future__ import annotations

from typing import Final

_HEX_PREFIX: Final = "0x"


def _strip_prefix(token: str) -> str:
    """Strip ``0x`` / ``0X`` and any leading/trailing whitespace."""
    s = token.strip()
    if s.lower().startswith(_HEX_PREFIX):
        s = s[2:]
    return s


def normalize_hex(value: str | int) -> str:
    """Canonical hex form: lowercase ``0x`` + stripped leading zeros.

    >>> normalize_hex("0x401000")
    '0x401000'
    >>> normalize_hex("0X401000")
    '0x401000'
    >>> normalize_hex("0x00401000")
    '0x401000'
    >>> normalize_hex(0x401000)
    '0x401000'
    """
    if isinstance(value, int):
        n = value
    else:
        s = _strip_prefix(value).replace("_", "")
        if not s:
            raise ValueError(f"empty hex string: {value!r}")
        # Detect decimal-vs-hex: if it has any a-f or starts with 0x we stripped,
        # treat as hex; otherwise still try int() with base 0.
        try:
            # base=16: explicit hex; raises if non-hex chars.
            n = int(s, 16)
        except ValueError:
            # Fallback: maybe the user passed a plain decimal-looking string.
            n = int(s, 10)
    if n < 0:
        raise ValueError(f"address must be non-negative: {value!r}")
    return f"{_HEX_PREFIX}{n:x}"


def to_int(addr: str) -> int:
    """Parse a canonical or near-canonical hex string to an int.

    >>> to_int("0x401000")
    4198400
    >>> to_int("401000")
    4198400
    >>> to_int("0x00401000")
    4198400
    """
    if isinstance(addr, int):
        return addr
    s = _strip_prefix(addr).replace("_", "")
    if not s:
        raise ValueError(f"empty address: {addr!r}")
    try:
        return int(s, 16)
    except ValueError as e:
        raise ValueError(f"not a valid hex address: {addr!r}") from e


def parse_addr_token(token: str, image_base: str | int | None) -> str:
    """Parse an arbitrary agent token into a canonical RVA string.

    Accepts:
        - ``"0x140001000"`` (VA, subtract image_base if image_base is set)
        - ``"401000"`` (bare hex; ambiguous — see below)
        - ``"0x1000"`` (small — treated as RVA)

    The decision rule for bare/ambiguous hex:
        - If ``image_base`` is set and the int >= image_base → treat as VA, subtract.
        - Else → treat as RVA.

    Symbol resolution (e.g. ``"main"``) is NOT handled here; that stays in
    GhidraTools so we can call into the JVM.
    """
    s = token.strip()
    if not s:
        raise ValueError("empty address token")
    n = to_int(s)
    if image_base is None:
        return normalize_hex(n)
    base = image_base if isinstance(image_base, int) else to_int(image_base)
    if n >= base:
        return normalize_hex(n - base)
    return normalize_hex(n)


def to_rva(addr: str | int, image_base: str | int | None) -> str:
    """Convert a VA to an RVA using the binary's image_base.

    Always returns a canonical ``0x`` lowercase hex string. Raises if
    ``image_base`` is ``None`` because there's no way to know the rebasing
    offset — use :func:`parse_addr_token` for that case.
    """
    if image_base is None:
        raise ValueError(
            "image_base is required to convert VA→RVA; "
            "use parse_addr_token() if you don't know the image_base"
        )
    n = addr if isinstance(addr, int) else to_int(addr)
    base = image_base if isinstance(image_base, int) else to_int(image_base)
    if n < base:
        raise ValueError(
            f"address 0x{n:x} is below image_base 0x{base:x}; "
            f"already an RVA? Use normalize_hex() if so."
        )
    return normalize_hex(n - base)


def to_va(rva: str | int, image_base: str | int) -> str:
    """Add image_base to an RVA. Returns canonical hex."""
    n = rva if isinstance(rva, int) else to_int(rva)
    base = image_base if isinstance(image_base, int) else to_int(image_base)
    return normalize_hex(n + base)
