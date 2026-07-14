# Changelog

All notable changes to **GhidraNexus** are documented in this file.

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
