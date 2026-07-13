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
| **Triage** | `survey_binary` (single-call snapshot of metadata, interesting functions / strings / imports / call graph) |
| **Read** | `decompile_function`, `disassemble`, `list_functions`, `list_imports`, `list_exports`, `search_strings`, `list_xrefs`, `gen_callgraph`, `read_bytes` |
| **Search** | `search_symbols_by_name`, `search_code` (semantic via ChromaDB) |
| **Write** | `rename_function`, `rename_variable`, `set_variable_type`, `set_function_prototype`, `set_comment` |
| **Lazy** | `wake_ghidra`, `ghidra_status` (HTTP transport only — boots JVM on first call) |

A complete list lands in `Implementations/phase-3-agent-api.md`.

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
