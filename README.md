<p align="center">
  <img src="https://github.com/user-attachments/assets/31c1831a-5be1-4698-8171-5ebfc9d6797c" width=60%>
</p>

<p align="center">
  <img alt="GitHub" src="https://img.shields.io/badge/version-0.3.0-blue?style=for-the-badge">
  <img alt="Status" src="https://img.shields.io/badge/status-active--development-orange?style=for-the-badge">
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-blue?style=for-the-badge">
  <img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-green?style=for-the-badge">
</p>

<p align="center"><b>GhidraNexus</b> — an agent-first Ghidra MCP server with a persistent notebook.</p>

---

## What is this?

GhidraNexus is a [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that exposes
[Ghidra](https://ghidra-sre.org/) to AI agents. It is a hard fork of
[`pyghidra-mcp`](https://github.com/clearbluejar/pyghidra-mcp), rewritten with one goal:

> **Make long-horizon reverse engineering possible for AI agents.**

Today this means: a single-thread JVM funnel that prevents Ghidra deadlocks, per-program locks for
safe concurrent binaries, lazy JVM activation so HTTP transports boot instantly, watchdog telemetry,
ChromaDB semantic indexing, and a stable tool surface.

Soon it means a **persistent notebook** — SQLite + FTS5 caches for every decompile / disassemble /
xref call, so the agent never re-decodes the same function twice and never forgets what it analyzed
yesterday. See `Implementations/` for the phase-by-phase plan.

---

## Quick start

```powershell
$env:GHIDRA_INSTALL_DIR = 'C:\Dev\Ghidra-MCP\ghidra_12.1.2_PUBLIC'

# stdio — for OpenCode / Claude Desktop / Cursor
uv run ghidra-nexus

# streamable-http — for `ghidra-nexus` CLI or remote agents
uv run ghidra-nexus --transport streamable-http --host 127.0.0.1 --port 8000

# GUI mode (shares state with the running Ghidra)
uv run ghidra-nexus --gui --transport streamable-http --project-path C:\Dev\Ghidra-MCP\ghidra-projects --project-name test
```

---

## Install

```bash
uvx ghidra-nexus   # ad-hoc run
uv tool install ghidra-nexus
```

Or local dev install:

```bash
git clone https://github.com/CloudyTabzy/ghidra-nexus
cd ghidra-nexus
uv sync --extra dev
uv run ghidra-nexus
```

---

## Tools at a glance

| Group | Examples |
|-------|----------|
| **Lifecycle** | `import_binary`, `delete_project_binary`, `analysis_status`, `save` |
| **Triage** | `survey_binary_fast` / `survey_binary_full`, `section_health` |
| **Read** | `decompile_function`, `disassemble`, `list_imports`, `list_exports`, `search_strings`, `list_xrefs`, `gen_callgraph`, `read_bytes` |
| **Search** | `search_symbols_by_name`, `search_code` (semantic via ChromaDB) |
| **Write** | `rename_function`, `rename_variable`, `set_variable_type`, `set_function_prototype`, `set_comment` |
| **Lazy** | `wake_ghidra`, `ghidra_status` (HTTP transport only — boots JVM on first call) |

---

## Agent onboarding workflow

```
1. import_binary(path)                 ← returns task_id + binary_name (queued)
2. analysis_status()                   ← poll until analysis_complete=true
3. section_health(binary_name)         ← catch encrypted / packed sections first
4. survey_binary_full(binary_name)     ← or survey_binary_fast while waiting
5. decompile_function / list_xrefs …   ← deep work
```

`import_binary` never claims analysis finished. It returns:

- `task_id` — correlator for this import
- `binary_name` — canonical name for every subsequent call
- `analysis_state` — `queued` | `loading` | `analyzing_functions` | `complete` | `failed`
- `function_count` — live count (0 until Ghidra finds functions)
- `project_path` / `nexus_data_dir` / `idb_path` — absolute paths to validate

`analysis_status` is the source of truth: live `function_count`, `sha256`,
`entropy_summary`, `path_warnings` (UAC-locked project paths), and
`recommended_tools` for the next call.

### `section_health`

Per-section Shannon entropy + classification:

| classification | entropy | recommendation |
|----------------|---------|----------------|
| `encrypted` | ≥ 7.0 | `dump_runtime` |
| `compressed` | 5.5–7.0 | `decompress` |
| `code` | low, executable | `analyze` |
| `data` | low, non-exec | `skip` |

Call this **before** a decompile storm on modern protected binaries.

---

## Agent-first error semantics

Recoverable tool failures return a **structured body** (not a framework re-raise):

```json
{
  "ok": false,
  "error_code": "encrypted_bytes",
  "message": "Decompilation produced no usable output",
  "hint": "Call disassemble(addr) for raw instructions, or section_health to confirm encryption.",
  "fallback_tool": "disassemble",
  "binary_name": "find.exe",
  "addr": "0x401000"
}
```

Invariants:

1. `error_code` is a stable string the agent can branch on.
2. `hint` is always present (one-sentence next step).
3. `fallback_tool` always names a **real registered tool** (never a ghost).
4. Decompile failures also set `error_code` / `hint` on each `DecompiledFunction`
   entry; `code` is empty on failure so agents do not treat error text as pseudo-C.

Tools that work **during** analysis (no hard block): `survey_binary_fast`,
`section_health`, `read_bytes`, `disassemble`, `list_exports`, `list_imports`,
`search_symbols_by_name`, `search_strings`. Deep tools (`decompile_function`,
`survey_binary_full`, renames) return `binary_analyzing` until analysis completes.

---

## Architecture (today)

```
MCP handlers (asyncio)
        │  executor.submit(program_info, fn)
        ▼
  GhidraExecutor  (single background thread, runs ALL Ghidra API calls)
        │  acquires program_info.rw_lock
        ▼
   Ghidra JVM  ── DecompilerPool (size=4) ── Watchdog (telemetry / stall / queue)
```

- Single JVM thread = zero `DecompInterface` deadlocks, zero write races
- Per-program `RLock` = different binaries truly parallel
- `DerivedState` (no stale flags) = every tool sees current pipeline state
- RE-MCP stdio pattern = JVM owns main thread, FastMCP runs as daemon

The **notebook** lands in Phase 1 (see `Implementations/`). After that, the architecture adds a
SQLite cache between the MCP handler and the executor so common reads are sub-millisecond.

---

## Repository layout

```
ghidra-nexus/                       ← THE repo
├── src/ghidra_nexus/               ← Python package
│   ├── server.py                   ← FastMCP entry, click CLI
│   ├── context.py                 ← PyGhidraContext, ProgramInfo
│   ├── ghidra_executor.py          ← single-thread JVM funnel
│   ├── decompiler_pool.py          ← size-4 thread-safe DecompInterface pool
│   ├── watchdog.py                 ← telemetry / stall / queue / error monitor
│   ├── tools.py                    ← GhidraTools (pure Ghidra API calls)
│   ├── mcp_tools.py                ← MCP tool handlers → executor dispatch
│   ├── indexing_mixin.py           ← ChromaDB semantic indexing
│   ├── notebook/                   ← **Phase 1+ — persistent notebook**
│   ├── models.py                   ← Pydantic request/response models
│   ├── project_spec.py             ← project path normalizer
│   ├── import_planning.py          ← import candidate planner
│   └── api_survey.py               ← single-call triage snapshot
├── tests/                          ← unit + integration
├── Implementations/                ← phase-by-phase engineering plan
└── README.md (this file)
```

---

## Contributing

This is a personal hard fork; there is no upstream to PR against. Phase work happens on long-lived
branches off `feature/notebook`. See `AGENTS.md` (workspace-level) for the engineering rules.

---

## License

Apache 2.0 — see `LICENSE`.
