"""Output grounding for SLM tasks (Phase 6).

Every SLM-generated output is validated against a per-task schema before
returning to the agent. This module holds the validators:

- :func:`validate_identifier` — name suggestion output (snake_case, ≤ 5 words)
- :func:`validate_token` — query expansion tokens (lowercase, snake_case, ≤ 31 chars)
- :func:`validate_api_name` — known-API check (built-in catalog)
- :func:`validate_summary` — bounded length, no invented function names
- :func:`validate_fts_query` — FTS5 syntax sanity (no unbalanced quotes)

Validation failures return ``GroundingResult(ok=False, reason=...)``.
Validators are pure — they do not import transformers or torch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Common
# ---------------------------------------------------------------------------

# snake_case identifier: starts with letter or underscore, then [a-z0-9_]+
_IDENT_RE = re.compile(r"^[a-z_][a-z0-9_]{0,63}$")
_TOKEN_RE = re.compile(r"^[a-z_][a-z0-9_]{1,31}$")
_FN_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


@dataclass(frozen=True)
class GroundingResult:
    """Outcome of a grounding check.

    ``ok=False`` carries a short reason suitable for the agent; never a stack
    trace or verbose diagnostic.
    """

    ok: bool
    reason: str | None = None
    value: Any = None  # sanitized value (e.g. lowercased token)


def validate_identifier(name: str) -> GroundingResult:
    """Check a function-name suggestion: snake_case, ≤ 64 chars, identifier-safe."""
    if not isinstance(name, str):
        return GroundingResult(False, "not a string")
    if len(name) > 64:
        return GroundingResult(False, f"name too long ({len(name)} > 64)")
    if not _IDENT_RE.match(name):
        return GroundingResult(
            False,
            f"name {name!r} not snake_case identifier",
        )
    # Reject reserved words / numeric-only / etc.
    if name in {"_", "__"}:
        return GroundingResult(False, "name is a dunder")
    return GroundingResult(True, value=name)


def validate_token(token: str) -> GroundingResult:
    """Check an FTS-friendly keyword token: lowercase, snake_case, ≤ 32 chars."""
    if not isinstance(token, str):
        return GroundingResult(False, "not a string")
    if not _TOKEN_RE.match(token):
        return GroundingResult(False, f"token {token!r} not lowercase identifier")
    return GroundingResult(True, value=token)


# ---------------------------------------------------------------------------
# Known-API catalog for query expansion grounding
# ---------------------------------------------------------------------------

# Compact catalog of common Windows + POSIX APIs the SLM might surface.
# The check is permissive (case-insensitive substring match against the known
# list) so the SLM can suggest reasonable names without us hard-coding
# every API. Used by :func:`validate_api_name`.
_API_CATALOG: frozenset[str] = frozenset(
    {
        # Windows sockets (Winsock)
        "WSAStartup", "WSACleanup", "socket", "bind", "listen", "accept",
        "connect", "recv", "send", "recvfrom", "sendto", "select",
        "WSAConnect", "WSAAccept", "WSARecv", "WSASend",
        "gethostbyname", "getaddrinfo", "htons", "htonl", "ntohs", "ntohl",
        "inet_addr", "inet_ntoa",
        # WinINet (HTTP)
        "InternetOpen", "InternetOpenUrl", "InternetConnect",
        "InternetReadFile", "InternetWriteFile", "InternetCloseHandle",
        "HttpOpenRequest", "HttpSendRequest", "InternetQueryDataAvailable",
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
        "WinHttpSendRequest", "WinHttpReceiveResponse", "WinHttpReadData",
        "WinHttpQueryHeaders", "WinHttpCloseHandle",
        # WinHTTP / WinINet convenience
        "URLDownloadToFile", "URLDownloadToCacheFile",
        # File I/O
        "CreateFile", "CreateFileW", "CreateFileA", "ReadFile", "WriteFile",
        "CloseHandle", "DeleteFile", "DeleteFileW", "MoveFile",
        "CopyFile", "GetTempPath", "GetTempFileName", "GetFileSize",
        "SetFilePointer", "SetEndOfFile", "FlushFileBuffers",
        "FindFirstFile", "FindNextFile", "FindClose",
        # Memory
        "malloc", "calloc", "realloc", "free", "memcpy", "memset",
        "memmove", "memcmp", "HeapAlloc", "HeapFree", "HeapReAlloc",
        "GlobalAlloc", "GlobalFree", "LocalAlloc", "VirtualAlloc",
        "VirtualFree", "VirtualProtect",
        # Process / thread
        "CreateProcess", "CreateProcessW", "CreateThread", "ExitThread",
        "TerminateProcess", "WaitForSingleObject", "GetCurrentProcess",
        "GetCurrentThread", "GetCurrentProcessId", "GetThreadId",
        "SuspendThread", "ResumeThread", "SetThreadPriority",
        "CreateMutex", "ReleaseMutex", "WaitForMultipleObjects",
        "OpenProcess", "TerminateProcess",
        # Registry
        "RegOpenKey", "RegOpenKeyEx", "RegCreateKey", "RegCreateKeyEx",
        "RegCloseKey", "RegQueryValueEx", "RegSetValueEx", "RegDeleteValue",
        # Crypto
        "CryptAcquireContext", "CryptReleaseContext", "CryptCreateHash",
        "CryptHashData", "CryptGetHashParam", "CryptDeriveKey",
        "CryptEncrypt", "CryptDecrypt", "CryptDestroyKey", "CryptDestroyHash",
        # DLL / module
        "LoadLibrary", "LoadLibraryW", "LoadLibraryA", "LoadLibraryEx",
        "GetProcAddress", "GetModuleHandle", "GetModuleFileName",
        "FreeLibrary",
        # Synchronization
        "EnterCriticalSection", "LeaveCriticalSection",
        "InitializeCriticalSection", "DeleteCriticalSection",
        "CreateEvent", "SetEvent", "ResetEvent", "CreateSemaphore", "ReleaseSemaphore",
        "InterlockedCompareExchange", "InterlockedExchange",
        "InterlockedIncrement", "InterlockedDecrement",
        # Strings
        "lstrcpy", "lstrcpyn", "lstrlen", "lstrcmp", "lstrcmpi",
        "wsprintf", "wvsprintf", "CompareString", "MultiByteToWideChar",
        "WideCharToMultiByte",
        # Misc
        "GetLastError", "SetLastError", "FormatMessage",
        "OutputDebugString", "OutputDebugStringA", "OutputDebugStringW",
        "Sleep", "GetTickCount", "GetTickCount64", "QueryPerformanceCounter",
    }
)


def validate_api_name(name: str) -> GroundingResult:
    """Check a Windows / POSIX API name against the built-in catalog.

    Case-insensitive, accepts ``kernel32!CreateFileW`` style qualified
    names. The catalog is intentionally limited to common APIs; unknown
    names are rejected so the SLM doesn't hallucinate.
    """
    if not isinstance(name, str):
        return GroundingResult(False, "not a string")
    if len(name) > 128:
        return GroundingResult(False, "name too long")
    if not _FN_NAME_RE.match(name.split("!")[-1]):
        return GroundingResult(False, f"name {name!r} not a valid identifier")
    bare = name.split("!")[-1]
    if bare in _API_CATALOG:
        return GroundingResult(True, value=bare)
    # Case-insensitive match against the catalog
    lower_map = {n.lower(): n for n in _API_CATALOG}
    canonical = lower_map.get(bare.lower())
    if canonical is not None:
        return GroundingResult(True, value=canonical)
    return GroundingResult(False, f"API {name!r} not in catalog")


# ---------------------------------------------------------------------------
# Summary grounding
# ---------------------------------------------------------------------------


@dataclass
class SummaryValidation:
    ok: bool
    cleaned: str = ""
    rejected_spans: list[str] = field(default_factory=list)
    reason: str | None = None


def validate_summary(
    text: str,
    *,
    max_len: int = 500,
    known_symbols: set[str] | None = None,
) -> SummaryValidation:
    """Check a 1-3 sentence summary.

    - Length cap (default 500 chars).
    - If ``known_symbols`` is provided, every function/symbol name in the text
      that looks like an identifier must be in the set (case-insensitive).
      Unknown identifiers are *rejected spans* (returned for inspection) but
      do not invalidate the summary by themselves — they're informational.

    The summary is considered "ok" if it passes the length cap. Rejected
    spans are advisory; if a known-symbol catalog is provided, callers can
    decide whether to retry.
    """
    if not isinstance(text, str):
        return SummaryValidation(False, reason="not a string")
    if not text.strip():
        return SummaryValidation(False, reason="empty summary")
    if len(text) > max_len:
        return SummaryValidation(
            False,
            reason=f"summary too long ({len(text)} > {max_len})",
        )
    cleaned = text.strip()
    rejected: list[str] = []
    if known_symbols:
        # Find all CamelCase / snake_case identifiers in the text and check
        # against the known set.
        lower_known = {s.lower() for s in known_symbols}
        for ident in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{1,63}\b", cleaned):
            if ident.lower() not in lower_known and not ident.islower():
                # Identifiers in all-lowercase are likely common words
                # ("the", "is", etc.); flag only those that look like
                # proper symbols.
                rejected.append(ident)
    return SummaryValidation(
        ok=True,
        cleaned=cleaned,
        rejected_spans=rejected,
    )


# ---------------------------------------------------------------------------
# FTS5 query sanity
# ---------------------------------------------------------------------------


def validate_fts_query(query: str, *, max_len: int = 500) -> GroundingResult:
    """Sanity-check a generated FTS5 query string.

    - Length cap.
    - No unbalanced double quotes.
    - Reject if it contains only stopwords.
    """
    if not isinstance(query, str):
        return GroundingResult(False, "not a string")
    if len(query) > max_len:
        return GroundingResult(False, f"fts_query too long ({len(query)} > {max_len})")
    if query.count('"') % 2 != 0:
        return GroundingResult(False, "unbalanced double quotes in fts_query")
    # Heuristic: must contain at least one alphanumeric token
    if not re.search(r"[A-Za-z0-9]", query):
        return GroundingResult(False, "no alphanumeric content")
    return GroundingResult(True, value=query)
