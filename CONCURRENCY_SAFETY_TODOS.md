# Concurrency-Safety TODOs — feature/concurrency-safety

Architectural improvements that the `feature/tools-expansion` work
surfaced. Each item: the problem, the proposed fix, the Ghidra-API /
code locations involved, and a complexity estimate. The intent is
that another agent can pick any of these up without re-discovering
the context.

Status legend: [ ] not started · [~] in progress · [x] done

## Why this list exists

The survey work in `feature/tools-expansion` (`api_survey.py`,
`survey_binary`, `survey_binary_fast`, `survey_binary_full`) hit
several architectural ceilings that didn't fit on the tools branch:

1. **Cold-start time dominated by upstream Ghidra analysis, not the
   survey itself.** Tools can't fix this — the executor is correctly
   serializing, but the analysis pipeline that runs *before* the
   survey call is doing 5-10 minutes of unnecessary work.
2. **No way for an agent to control the analysis profile.** Today
   the only knob is `--no-symbols`. We need a way to say "import
   this binary for triage, not for decompilation".
3. **The GhidraExecutor is the wrong place for PDB downloads.** The
   executor's job is to serialize JVM access. Network I/O blocks it
   unnecessarily.

These belong on `feature/concurrency-safety` (architectural) —
not on `feature/tools-expansion` (additive tools).

---

## Tier 1 — Speed (do these first; they unblock every other tool)

### [ ] Default `--no-symbols=true`; add `--with-symbols` opt-in flag
**Problem:** pyghidra-mcp currently runs
`setup_symbol_server(...)` + `set_remote_pdbs(program, True)` on every
binary. For find.exe that means a 30MB PDB download from
`msdl.microsoft.com` blocking the GhidraExecutor for 30-60s. This is
**50-80% of the first-time analysis wall time** for any Windows binary.

**Fix:** In `context.py::analyze_program`, default `no_symbols=True`
(matching what every other RE tool does — IDA does not download
PDBs by default). Add a `--with-symbols` CLI flag for users who
want the additional symbol resolution.

**Files:** `src/pyghidra_mcp/server.py` (add `--with-symbols` click
option), `src/pyghidra_mcp/context.py::analyze_program` (flip
default).

**Complexity:** S (one-line behavior change + one new CLI flag).

**Risk:** Existing users who relied on PDB auto-download will lose
it. Document the change in the commit message and AGENTS.md. The
GZF cache means switching back is a one-time cost per binary.

**Validation:** Re-run `tests/integration/test_import_binary.py` with
a real Windows binary; cold start should drop from 5-10 min to
30-60s.

### [ ] Add `--no-decompiler` flag (and a global `--fast-analysis` shorthand)
**Problem:** Even with PDB disabled, Ghidra's `analyzeAll` runs the
Decompiler analyzers (`Decompiler Parameter ID`, `Decompiler Stack
Reference Recovery`, `Call Fixup`, `Call Convention ID`). For find.exe
these add another 1-3 minutes on top of function discovery. They're
needed only for high-quality decompilation, not for survey / list
/ search / xref tools.

**Fix:** Add a `no_decompiler` constructor flag in
`PyGhidraContext.__init__` (parallel to `no_symbols`). When set, the
relevant analyzers are disabled before `flat_api.analyzeAll`. Add
a CLI flag `--no-decompiler/--with-decompiler` and a shorthand
`--fast-analysis` that sets both `no_symbols=True` and
`no_decompiler=True`.

**Files:** `src/pyghidra_mcp/context.py` (add `no_decompiler`
arg + `set_analysis_option("Decompiler Parameter ID", False)` etc.
in `analyze_program`), `src/pyghidra_mcp/server.py` (CLI flags).

**Complexity:** S.

**Risk:** `decompile_function` quality drops (no parameter IDs,
no stack variable analysis) when `no_decompiler=True`. The handler
should detect this and return a clear warning. Possible mitigation:
make `decompile_function` re-analyze on-demand (with the decompiler
analyzers enabled) for the one function being decompiled. That's
expensive but only when actually needed.

### [ ] Per-binary analysis profile: `import_binary(fast=True)`
**Problem:** Today the analysis profile is fixed at server start.
If a server is launched with `--fast-analysis`, every binary gets
fast analysis — including ones the user wants to fully decompile.
If launched without it, every binary pays the full cost.

**Fix:** Add a `fast: bool` parameter to `import_binary` /
`import_binary_backgrounded`. When True, the per-binary analysis
runs with `no_symbols=True` and `no_decompiler=True`. When False,
the default server settings apply.

**Files:** `src/pyghidra_mcp/context.py` (thread the parameter
through), `src/pyghidra_mcp/mcp_tools.py::import_binary` (expose it
as a tool parameter), `src/pyghidra_mcp/models.py` (Pydantic model).

**Complexity:** M (needs to flow through `_import_candidates`,
`import_binary`, `analyze_program` without breaking the
existing path).

**Risk:** Per-binary analysis profile means we can't re-use the
GZF cache when a user re-imports the same binary with `fast=True`
after importing it with `fast=False` (different analyzer set).
Either (a) re-import is fine and Ghidra overwrites, (b) we need
to version GZFs by analysis profile.

### [ ] Move PDB download off the GhidraExecutor
**Problem:** `setup_symbol_server` and `set_remote_pdbs` configure
Ghidra's symbol server; the actual download happens inside
`flat_api.analyzeAll` which runs on the GhidraExecutor. Network
I/O is blocking the only JVM-touching thread, which means other
in-flight tool calls (e.g. another `list_project_binaries`) wait
for the PDB download to complete.

**Fix:** Pre-download the PDB to the local symbol cache *before*
submitting the analyze task to the executor. The Ghidra PDB loader
will find the file in the local cache and skip the download.

**Files:** `src/pyghidra_mcp/context.py` (add a `_prefetch_pdb()`
helper that runs on the import thread, before `analyze_program`
is submitted), `src/pyghidra_mcp/ghidra_executor.py` (no changes
needed if we keep using `setup_symbol_server`).

**Complexity:** M (requires figuring out Ghidra's PDB URL format to
manually fetch — it's not always `msdl.microsoft.com`).

**Risk:** Low. The download still happens; it just happens earlier
and on a non-executor thread.

## Tier 2 — Concurrency primitives

### [ ] Notification on binary-ready (instead of polling)
**Problem:** Today the agent's only signal that a freshly imported
binary is ready for tools is to poll `list_project_binaries`
until `analysis_complete=true`. With 5-10 min cold start and
a 60s poll interval, agents spend real wall-clock time doing
nothing while waiting.

**Fix:** Add a `wait_for_binary(binary_name, timeout_s=600)` tool
that blocks (on the MCP server side) until the binary is ready.
Server-side, the import thread's `_import_done_callback` already
fires when the binary is ready — just expose it via a
`threading.Event` per `ProgramInfo` and have the new tool
`event.wait(timeout=timeout)`.

**Files:** `src/pyghidra_mcp/context.py` (add `_ready_event:
threading.Event` to `ProgramInfo`, set it in `_import_done_callback`),
`src/pyghidra_mcp/mcp_tools.py` (new `wait_for_binary` tool),
`src/pyghidra_mcp/models.py` (response model), `src/pyghidra_mcp/server.py`
(register the tool).

**Complexity:** S.

**Risk:** Minimal. Long-polling clients (OpenCode) handle blocked
tool calls fine. Existing `analysis_status` polling remains for
backward compat.

### [ ] GhidraExecutor task cancellation
**Problem:** When a `decompile_function` call times out (default 30s)
or a `survey_binary_full` call is too long, the JVM task is still
running. The executor returns the timeout to the caller but the JVM
thread is busy doing work nobody is waiting for. This wastes the
single-threaded executor and can stall subsequent tool calls.

**Fix:** Add a `cancel()` method to the GhidraExecutor that signals
the in-flight task to stop. For Ghidra, this requires
`monitor.checkCancelled()` calls in the analyzer paths — we'd
need to inject a cancellable monitor into the analysis. For
decompile, set `decomp.setTimeout` and check on the way.

**Files:** `src/pyghidra_mcp/ghidra_executor.py` (add cancel
mechanism with cooperative interrupts), `src/pyghidra_mcp/context.py`
(use a `CancellableTaskMonitor` in `analyze_program`).

**Complexity:** L. Cooperative cancellation in Ghidra is invasive —
the analyzers need to check the monitor. Realistic alternative:
fire-and-forget the timeout'd task (let it finish, but don't wait).
That doesn't free the executor but it doesn't waste the calling
thread either.

**Risk:** Cancellation in middle-of-analyzer can leave the Ghidra
program in a partially-modified state. Safer to NOT cancel and
let the task finish — the GhidraExecutor's queue discipline still
serializes subsequent calls.

### [ ] Multi-lane executor (read-only vs write)
**Problem:** The current executor is a single FIFO queue. A
`survey_binary_fast` (read-only, milliseconds) is blocked behind
a `decompile_function` (write, 5+ seconds) even though the two
operations don't conflict at the JVM level — Ghidra allows
multiple readers in parallel as long as no writer is active.

**Fix:** Add lane separation: `executor.submit_read_only(fn)` and
`executor.submit_write(fn)`. Reads can run concurrently with each
other; writes get exclusive access (no reads while a write is
running).

**Files:** `src/pyghidra_mcp/ghidra_executor.py` (rewrite as a
two-lane queue), `src/pyghidra_mcp/mcp_tools.py` (mark each
handler `read_only=True` or `read_only=False`).

**Complexity:** L. The JVM allows parallel reads via
`program.getCurrentProgram()`'s reference counting, but the
Ghidra Python API doesn't always expose this cleanly. Need to
audit each tool.

**Risk:** Medium. Some Ghidra operations are documented as
single-thread-only even for reads. Trial-and-error on real binaries
to find the safe set.

## Tier 3 — Reliability

### [ ] Streamable-HTTP reconnect on GET stream drop
**Problem:** The MCP streamable-http transport's GET stream
occasionally disconnects during long-running requests (we hit this
in the manual e2e test). The client reconnects but loses in-flight
responses. For 5-10 minute analyses this is a real reliability
issue.

**Fix:** Add a retry layer in the client (or use a long-poll
pattern that survives disconnects). On the server side, ensure
all responses are flushed before the GET can disconnect.

**Files:** `src/pyghidra_mcp/proxy.py` (if the proxy is involved),
`tests/manual/manual_survey_e2e.py` (verify the fix).

**Complexity:** M.

**Risk:** Mostly an upstream MCP issue. Document the workaround
in AGENTS.md and recommend stdio transport for long-running
operations.

### [ ] Per-program decompiler pool sizing
**Problem:** The decompiler pool is fixed at 4 instances per
program. For tiny binaries this is wasteful (4 DecompInterface
instances sitting idle). For huge binaries (10k+ functions) it
might be too small — 4 parallel decompiles is not enough for
analyze_batch parallelism.

**Fix:** Size the pool based on binary size: `pool_size = min(8,
max(1, total_functions // 1000))`. Allow the user to override via
a CLI flag `--decompiler-pool-size=N`.

**Files:** `src/pyghidra_mcp/decompiler_pool.py` (constructor
takes a size), `src/pyghidra_mcp/context.py::_create_decompiler_pool`
(passes the dynamic size), `src/pyghidra_mcp/server.py` (CLI flag).

**Complexity:** S.

### [ ] Health endpoint for monitoring
**Problem:** Production agents / orchestrators have no way to
ask "is the GhidraExecutor stuck?" or "what's the current queue
depth?". The watchdog logs warnings but there's no programmatic
interface.

**Fix:** Add an `executor_health()` tool that returns:
`active_calls`, `queue_depth`, `recent_error_count`,
`oldest_pending_task_age_s`. Add similar metrics for the
decompiler pool, the watch-dog state, and the import executor.

**Files:** `src/pyghidra_mcp/mcp_tools.py` (new tool),
`src/pyghidra_mcp/ghidra_executor.py` (expose stats), models.py.

**Complexity:** S.

## Tier 4 — Future / nice-to-have

### [ ] Auto-save on program deallocation
**Problem:** Programs that get deleted via `delete_project_binary`
may not have their Ghidra-side resources (decompiler pool, symbol
cache) cleaned up. Memory pressure grows with binary count.

**Files:** `src/pyghidra_mcp/context.py::delete_program`.

**Complexity:** S. (probably already mostly done — verify with a
stress test).

### [ ] Bulk function completeness report
**Problem:** `analyze_function_completeness` is per-function.
For a survey that says "12 functions have grade F", the agent
needs 12 separate calls. A bulk version would sort the
binary's functions by completeness and return the worst-N in one
call.

**Files:** `src/pyghidra_mcp/api_analysis.py` (the proposed
module; not yet written), tools.py, mcp_tools.py, server.py.

**Complexity:** M.

### [ ] Memory-bounded string tables
**Problem:** Ghidra's `DefinedStringIterator` for a 50MB binary
returns millions of strings. Survey caps at 5000, but if an agent
calls `search_strings(query="")` they get the full table dumped
into context. Need a streaming variant.

**Files:** `src/pyghidra_mcp/tools.py::search_strings`.

**Complexity:** S.

## Workflow

When you (or another agent) pick an item from this list:

1. Switch to `feature/concurrency-safety` (per AGENTS.md).
2. Make the change. Architectural changes go here, NOT on
   `feature/tools-expansion`.
3. If the change is user-visible (new flag, new tool), update
   AGENTS.md and `pyproject.toml` if needed.
4. If a tools-branch feature depends on the new architecture,
   the tools branch can pull via rebase — but DON'T merge
   tools work into this branch.
5. Add unit tests (mock-based, executor mocking) in `tests/unit/`.
6. Add integration tests in `tests/integration/` if the change
   affects the MCP tool surface.
7. Commit on `feature/concurrency-safety`. Push to origin.

Reference: the GhidraExecutor funnel pattern in
`src/pyghidra_mcp/ghidra_executor.py` and the
`ProgramInfo.rw_lock` discipline in `src/pyghidra_mcp/context.py`
are the existing architectural pieces — extend those, don't
replace.
