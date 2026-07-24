# Changelog

All notable changes to **GhidraNexus** are documented in this file.

## [0.4.0] — Hook-porting fidelity

### Added
- **`disassemble_call_site`** — per-CALL stack evidence for hook porting:
  push/`MOV [sp+X]` writes with call-time stack offsets, one-level register
  resolution, ECX `this` evidence, caller-cleanup bytes, calling-convention
  inference with explicit confidence, and a P-code cross-check fallback when
  listing evidence is thin. Catches non-standard push orders that decompiler
  pseudocode hides.
- **`verify_port`** — pre-flight check of a proposed ported signature against
  `ret N` epilogues and call-site push evidence, with register-clobber
  analysis (`saved_registers` / `clobbered_volatile` /
  `clobbered_non_volatile`).
- **Verdict memory** — `verify_port` results persist in the new
  `port_verifications` table (schema v4, migration
  `004_port_verifications.sql`); re-runs surface `prior_verdict` and warn on
  signature drift.
- **Knowledge-plane FTS coverage** — hypotheses, aliases, and failure
  breadcrumbs (`error_code` only) are now indexed, so `notebook_search`
  recalls prior findings. Plain breadcrumbs are deliberately not indexed to
  keep FTS signal clean.
- Schema migration `003_call_sites.sql` — gzipped per-function call-site
  analysis cache with extractor → view → FTS → embed pipeline.

### Fixed
- **streamable-http daemon startup crash**: `server.py` called an undefined
  `_register_lazy_tools` (NameError on cold start). The lazy path now
  registers `wake_ghidra` + `ghidra_status` as intended.
- Latent `sqlite3` NameError in the breadcrumb archive fallback path
  (`sqlite3` was TYPE_CHECKING-only but used at runtime).

### Tests
- 31 new unit tests in round 1 (`test_callsite_analysis.py`,
  `test_callsite_cache.py`, `test_disassemble_call_site.py`,
  `test_verify_port.py`) and 20 more in round 2 (register classification,
  P-code fallback predicate, port-verification persistence, FTS recall).
- Suite total: 502 passed, 1 skipped.

## [0.3.0] — Phase 5 (Polish)

### Added
- **Knowledge-plane status in `analysis_status`**: per-binary `binary_class`,
  `analysis_ready`, `cached_decompiles`, `cached_disassemblies`, `artifact_views`,
  `embedded_count`, `vec_status`, `vec_index_complete`, `embed_progress`,
  `embed_target`, and `embed_model`.
- **Hard gates for large binaries**:
  - `search_strings` refuses empty/short (< 3 characters) queries on
    `very_large` binaries with a typed `invalid_params` error and
    `notebook_search` fallback.
  - `search_code` refuses empty queries on `large`/`very_large` binaries and
    degrades gracefully when sqlite-vec is unavailable or still indexing.
- **Maintenance tools**:
  - `notebook_archive_breadcrumbs` — copy old breadcrumbs to
    `breadcrumbs_archive` and delete them from the hot table.
  - `notebook_vacuum` — delete stale decompile/disassembly generations and
    optionally run `VACUUM`.
- Schema migration `002_breadcrumbs_archive.sql` for long-term audit storage.

### Changed
- **ChromaDB is now optional and second-class.** `chromadb>=1.3.5` moved from
  core dependencies to `[project.optional-dependencies] chromadb`.
- `search_code` default backend is notebook/sqlite-vec hybrid; legacy ChromaDB
  path is gated behind `NEXUS_SEMANTIC_BACKEND=chromadb`.
- Refactored `_build_program_info` into focused helpers to keep complexity under
  the ruff threshold.
- `CodeSearchResults` now carries `reliability_notes` for agent-visible fallback
  explanations.

### Tests
- Added `tests/unit/test_phase5_gates.py` covering very_large string-scan and
  semantic-search degrade paths.
- Added `tests/unit/test_phase5_maintenance.py` covering breadcrumb archiving
  and vacuum.
- Updated `tests/unit/test_notebook_schema.py` for schema version 2 and the
  `breadcrumbs_archive` table.
