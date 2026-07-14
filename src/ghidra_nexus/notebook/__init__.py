"""GhidraNexus Notebook — persistent knowledge plane for long-horizon RE.

The :class:`Notebook` is the Python API consumed by MCP tools and CLI alike.
It owns one SQLite file per project and exposes sub-managers for every table.
"""

from .addresses import normalize_hex, parse_addr_token, to_int, to_rva, to_va
from .pagination import (
    MAX_LIMITS,
    DEFAULT_LIMITS,
    PageWindow,
    clamp_limit,
    validate_offset,
    window_list,
    window_text,
)
from .scale import BinaryScale, classify_binary
from .store import Notebook, NotebookConfig

__all__ = [
    # Core
    "Notebook",
    "NotebookConfig",
    # Scale (F1)
    "BinaryScale",
    "classify_binary",
    # Addresses (F5)
    "normalize_hex",
    "parse_addr_token",
    "to_int",
    "to_rva",
    "to_va",
    # Pagination (F6)
    "DEFAULT_LIMITS",
    "MAX_LIMITS",
    "PageWindow",
    "clamp_limit",
    "validate_offset",
    "window_list",
    "window_text",
]
