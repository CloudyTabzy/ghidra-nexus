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
a stable tool surface, and a **persistent notebook** — SQLite + FTS5 caches for every decompile /
disassemble / xref call, plus sqlite-vec hybrid semantic search.

ChromaDB is still supported via `NEXUS_SEMANTIC_BACKEND=chromadb` but is now an optional,
second-class backend. The default knowledge plane is entirely local SQLite.

See `Implementations/` for the phase-by-phase plan.

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
| **Hook porting** | `disassemble_call_site` (per-CALL push/stack-offset evidence + convention confidence + P-code cross-check), `verify_port` (pre-flight signature check with register-clobber analysis; verdicts are remembered and prior ones surface on re-runs), `override_callsite_signature` (fix the ABI in Ghidra at one call site), `generate_hook_stub` (Zig/C stub from the same evidence) |
| **Search** | `search_symbols_by_name`, `search_code` (sqlite-vec hybrid; ChromaDB optional) |
| **Write** | `rename_function`, `rename_variable`, `set_variable_type`, `set_function_prototype`, `set_comment` |
| **Notebook** | `notebook_summary`, `notebook_search`, `notebook_breadcrumbs`, `notebook_alias`, `notebook_hypothesis`, `notebook_embed_status`, `notebook_rebuild_embeddings`, `notebook_archive_breadcrumbs`, `notebook_vacuum` |
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
`entropy_summary`, `path_warnings` (UAC-locked project paths), cache counters
(`cached_decompiles`, `cached_disassemblies`, `artifact_views`, `embedded_count`),
vec readiness (`vec_available`, `vec_index_complete`, `embed_progress`), and
`recommended_tools` for the next call.

## Knowledge plane

Every read-heavy tool checks the notebook SQLite cache first. On miss, the full
blob is gzipped and stored, a distilled `summary` + `key_entities` view is
extracted, FTS5 is updated, and the view is queued for sqlite-vec embedding.

```
MCP handler
    │  cache hit → windowed response (offset/limit/has_more)
    ▼
Ghidra executor (JVM) → gzipped blob
    ▼
Extractor → artifact_view (summary + entities)
    ▼
FTS5 + sqlite-vec
```

### Pagination defaults

| Tool | Default limit | Max |
|------|--------------:|----:|
| `decompile_function` | 200 lines | 1,000 |
| `disassemble` | caller's `count` | 200 insns |
| `list_xrefs` | 50 | 500 |
| `search_strings` | 100 | 1,000 |
| `search_code` | 5 | 50 |
| `notebook_breadcrumbs` | 50 | 500 |

### `search_code` modes

- `hybrid` (default): FTS5 + sqlite-vec KNN → RRF merge.
- `literal`: FTS5 only; works even when vec is unavailable.
- `semantic`: sqlite-vec KNN only. Returns a typed error if vec is unavailable,
  or FTS-only partial results with a note if the index is still building.

Set `NEXUS_SEMANTIC_BACKEND=chromadb` to use the legacy ChromaDB path; it is
not recommended for new projects.

### Maintenance

- `notebook_archive_breadcrumbs(age_days=30)` — move old audit crumbs to
  `breadcrumbs_archive` and delete them from the hot table.
- `notebook_vacuum(keep_generations=2, run_vacuum=False)` — delete stale
  decompile/disassembly generations and optionally `VACUUM` the SQLite file.
- `notebook_rebuild_embeddings(binary_name=None)` — drop and re-queue embeddings
  after a model change or stuck index.

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
        │  notebook cache first (SQLite + FTS5 + sqlite-vec)
        ▼
  GhidraExecutor  (single background thread, runs ALL Ghidra API calls)
        │  acquires program_info.rw_lock
        ▼
   Ghidra JVM  ── DecompilerPool (size=4) ── Watchdog (telemetry / stall / queue)
```

- Single JVM thread = zero `DecompInterface` deadlocks, zero write races
- Per-program `RLock` = different binaries truly parallel
- Notebook cache-first = sub-millisecond reads, full provenance, no re-decode
- sqlite-vec = primary semantic backend; ChromaDB optional via env var
- RE-MCP stdio pattern = JVM owns main thread, FastMCP runs as daemon

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
│   ├── indexing_mixin.py           ← optional ChromaDB backend
│   ├── notebook/                   ← persistent SQLite knowledge plane
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
