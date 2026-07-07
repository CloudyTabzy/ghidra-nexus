# Tools-Expansion TODOs — feature/tools-expansion

Prioritized list of binary-analysis tools to port from Synapse MCP to
pyghidra-mcp. Each row includes: the tool name, what it does, why we
want it, the IDA equivalent (and which API file holds the reference impl),
the rough Ghidra-API mapping, and an estimated complexity.

Status legend: [ ] not started · [~] in progress · [x] done

## Tier 1 — Core RE workflow (do these first)

### [ ] analyze_function (Synapse)
**What:** Single function's full dossier — decompilation, callers,
callees, strings, constants, xrefs, basic blocks, prototype, in one call.
**Why:** Today an agent needs ~7 tool calls to gather the same info
(decompile_function + list_xrefs + get_callees + get_referenced_strings
+ get_basic_blocks + get_function_prototype + ...). One call = no
context churn.
**IDA:** `api_analysis.py::analyze_function` (~300 LOC).
**Ghidra API:** mostly composition of existing pyghidra-mcp tools
(tools.py has decompile_function, get_callees, get_referenced_strings,
get_basic_blocks, list_xrefs).
**Complexity:** S (a thin orchestrator that calls the existing
GhidraTools methods and bundles the result).

### [ ] func_profile (Synapse)
**What:** Per-function metrics only (size, instr count, block count,
caller/callee counts, strings, constants) WITHOUT the decompilation.
**Why:** A cheap "what does this function look like?" probe that
agents can call on dozens of functions during triage without burning
context on pseudocode. Pairs naturally with `survey_binary` for
"show me the top-15 functions, then profile each one in parallel".
**IDA:** `api_analysis.py::func_profile`.
**Ghidra API:** same as analyze_function minus the decompilation step.
**Complexity:** S.

### [ ] analyze_batch (Synapse)
**What:** Configure-and-run analyze_function on N targets. Each
target picks which sections to include (decompile, disasm, xrefs,
callers, callees, strings, constants, basic blocks).
**Why:** A bulk analyze_function with fine-grained per-section toggles.
For example, an agent investigating a `dispatcher` might ask for
decompile + xrefs + callees across 10 caller functions.
**IDA:** `api_analysis.py::analyze_batch`.
**Ghidra API:** same as analyze_function; complexity is the per-section
config Pydantic model.
**Complexity:** M.

### [ ] xref_query (Synapse)
**What:** Direction- and type-filtered xref search with pagination.
Today pyghidra-mcp's `list_xrefs` returns ALL xrefs to an address with
no filtering. For a heavily-referenced function like `printf`, the
agent gets flooded with hundreds of unrelated references.
**Why:** Filter by (direction=to/from/both, xref_type=any/code/data)
and paginate. Critical for handling real-world binaries where single
functions have 500+ xrefs.
**IDA:** `api_analysis.py::xref_query`.
**Ghidra API:** `ReferenceManager.getReferencesTo(addr)` /
`getReferencesFrom(addr)` plus `ReferenceType` filtering. Already
exposed via `tools.list_xrefs`, just needs the filter/paginate wrapper.
**Complexity:** S.

### [ ] search_code (semantic) — verify GhidraTools equivalent exists
**What:** Synapse's `search_code` is the semantic search. Verify that
pyghidra-mcp's `search_code(query, search_mode="semantic")` covers
the same scope (ChromaDB indexing, similarity threshold, etc.).
**Why:** We're already using this in tests; just want to confirm the
parity and add a "find the function that does X" agent-facing
docstring. (May not need a new tool — just a docstring upgrade.)
**Complexity:** XS (no new code, possibly a docstring + test).

### [ ] get_function_callers (Synapse `get_function_callers`)
**What:** Direct callers of a function with the call-site addresses
included (not just the function name).
**Why:** An agent investigating a function usually wants to know
"which line in which other function calls me?" not just "I'm called
by these 4 functions". Today `list_xrefs` returns call sites but mixes
data and code xrefs.
**IDA:** `api_analysis.py::get_function_callers`.
**Ghidra API:** `ReferenceManager.getReferencesTo(addr)` filtered to
`RefType.isCall()`.
**Complexity:** S.

### [ ] callgraph (multi-root) — extend `gen_callgraph`
**What:** pyghidra-mcp already has `gen_callgraph` but it's per-root.
Add a `callgraph(roots=[...], max_depth, max_nodes)` variant for the
"give me everything reachable from these 3 entrypoints" use case.
**Why:** Survey reports the top-3 call-graph roots; an agent should
be able to materialise the full topology in one call.
**IDA:** `api_analysis.py::callgraph`.
**Ghidra API:** already used by the existing gen_callgraph (Mermaid
output); just need the multi-root wrapper.
**Complexity:** S.

### [ ] get_function_signature / set_function_prototype — verify
**What:** Synapse has separate `get_function_signature` and
`set_function_prototype`; pyghidra-mcp has `set_function_prototype`
but no `get_function_signature`. Add the read path.
**Why:** Agents writing decompiler commentary or new variables need
to know "what's the current signature before I propose a change?"
**Complexity:** S (decompiler.getSignature() or tinfo_t on Program).

## Tier 2 — Deeper analysis

### [ ] apply_flirt_signature (Synapse)
**What:** Apply a FLIRT signature pack to identify library functions
in the current IDB. Without FLIRT, every Windows binary looks like
it has 800 user-defined functions when most are CRT + Win32 + STL.
**Why:** Survey already counts library_functions vs user-defined, but
the actual library identification depends on FLIRT. Right now
Ghidra's auto-analysis only runs FLIRT if the .gdt files include it.
**IDA:** `api_flirt.py`.
**Ghidra API:** `ghidra.app.decompiler.analysis.DecompilerParameterIDAnalyzer`
plus the bundled .gdt/sig packs. Or the GhidraScriptingManager
`applySignatures` script.
**Complexity:** M (depends on whether the .gdt pack has the sigs we
need).

### [ ] find_xor_pattern / xor_invert (Synapse)
**What:** Detect XOR obfuscation loops in a function and recover the
key. Invert a known ciphertext with a known plaintext to recover a
multi-byte key.
**Why:** This is THE first thing a malware analyst runs on
suspicious binaries. 50%+ of obfuscated malware uses XOR loops.
**IDA:** `api_analysis.py::find_xor_pattern`,
`api_analysis.py::xor_invert`.
**Ghidra API:** `program.getListing().getInstructions(body)` scan for
XOR-immediate loops, then `xor_invert(addr, plaintext)` reads the
ciphertext via memory.getBytes.
**Complexity:** M.

### [ ] trace_data_chain (Synapse)
**What:** Multi-hop data-flow trace backward from a sink. "Where does
the value passed to VirtualAlloc come from?" goes up the call stack
through register loads, through more calls, eventually to a network
recv.
**Why:** Single most powerful reverse-engineering primitive. Answers
the question every analyst asks: "where did this value come from?"
**IDA:** `api_analysis.py::trace_data_chain` (~400 LOC; uses
Hex-Rays microcode def-use chains via the `register=` arg).
**Ghidra API:** no direct equivalent. Options: (a) emulate with
Ghidra's P-code via `ghidra.pcode.exec.PcodeExecutor` (heavy),
(b) use `ghidra.app.decompiler.DecompInterface` then walk ctree to
track identifier->expression back through assignments, (c) fall
back to a simpler iterative call-graph + register-arg trace.
**Complexity:** L. (a) and (b) require either the decompiler
(PcodeExecutor isn't in vanilla Ghidra 12.1) or ctree traversal.

### [ ] get_function_jump_targets (Synapse)
**What:** Every jump instruction in a function (jmp, je, jne, jg, etc.)
with the resolved target address.
**Why:** Quick CFG sketch for a function — agents can identify
branch-heavy logic, switch statements, tail-calls, indirect jumps
(possible vtable dispatch).
**IDA:** `api_analysis.py::get_function_jump_targets`.
**Ghidra API:** iterate function's instructions, for each one with a
flow type, read `Instruction.getFlows()`.
**Complexity:** S.

### [ ] get_function_hash (Synapse)
**What:** SHA-256 of normalized function bytes (address-typed
operands zeroed). Used to identify identical functions across builds.
**Why:** Patch-diffing two versions of the same binary — "did they
patch this function or replace it?" Function-level hash is the
quickest answer.
**IDA:** `api_analysis.py::get_function_hash` (and bulk version).
**Ghidra API:** `Listing.getCodeUnitsContaining(body, monitor)`,
extract bytes via `Memory.getBytes(addr, buf)`, hash.
**Complexity:** S.

### [ ] find_similar_functions (Synapse)
**What:** CFG/feature-vector similarity search — "find me all
functions in this binary that look like memcpy". Identifies vendor
libraries or known-good patterns.
**Why:** Useful for spotting copy-pasted code, finding custom
implementations of standard functions, fingerprinting packers.
**IDA:** `api_analysis.py::find_similar_functions` (~600 LOC; uses
NetworkX for CFG similarity + numpy for feature vectors + a built-in
fingerprint DB for memcpy/memset/strlen/etc).
**Ghidra API:** `networkx` for CFG (already a dep via angr;
pyghidra-mcp may need to add it), Ghidra's `Function.getBody()` for
CFG. The fingerprint DB is hand-rolled.
**Complexity:** L (this is a 600-LOC feature).

### [ ] diff_functions (Synapse)
**What:** Side-by-side diff of two decompiled functions, with a
similarity ratio. "What did they change in this function between
v1.0 and v1.1?"
**Why:** Patch diffing, regression analysis, understanding malware
variant evolution.
**IDA:** `api_analysis.py::diff_functions` (uses
`difflib.SequenceMatcher` on pseudocode).
**Ghidra API:** decompile both, run `difflib.SequenceMatcher` on the
two pseudocode strings.
**Complexity:** S.

## Tier 3 — Static-analysis deep cuts

### [ ] analyze_function_completeness (Synapse)
**What:** Per-function "how well documented is this in the IDB?"
score 0-100 with a letter grade. 5 weighted criteria: custom name
(35), type annotation (25), function comment (20), named stack
vars (15), inline comments (5). Grade: A ≥ 90, F < 20.
**Why:** Drives the agent's "where to focus my reverse-engineering
effort" decisions — function with grade F = needs the most work.
**IDA:** `api_analysis.py::analyze_function_completeness`.
**Ghidra API:** read symbol comment + decompiler param names + listing
comments — mostly already in tools.py.
**Complexity:** S.

### [ ] get_basic_blocks (Synapse `basic_blocks`)
**What:** List all basic blocks of a function with their start, end,
size, type, and predecessor/successor lists. Optionally with disasm.
**Why:** Lets agents draw their own CFG without paying for
gen_callgraph when they just want the BB structure.
**IDA:** `api_analysis.py::basic_blocks`.
**Ghidra API:** `BasicBlockModel` (already used in mcp_tools
internally).
**Complexity:** S.

### [ ] find_bytes (Synapse)
**What:** Search for raw byte patterns with `?` wildcards. Critical
for finding gadgets, hidden strings, shellcode, packed regions.
**Why:** Today pyghidra-mcp has no byte-pattern search.
**IDA:** `api_analysis.py::find_bytes`.
**Ghidra API:** `Memory.findBytes(start, end, pattern, mask,
monitor)` or `BinaryReader`.
**Complexity:** S.

### [ ] insn_query (Synapse)
**What:** Search for instruction patterns by mnemonic + operand
filter. e.g. "all `call [reg+0x40]` instructions in this range"
(vtable dispatch — `0x40` is the IDXGISwapChain::Present slot).
**Why:** Spot vtable calls, syscall stubs, anti-debug patterns, etc.
**IDA:** `api_analysis.py::insn_query`.
**Ghidra API:** iterate `Listing.getInstructions(range)`, filter by
mnemonic and operand types.
**Complexity:** M.

### [ ] export_funcs (Synapse)
**What:** Export function data as JSON / c_header / prototypes for
sharing with other tools. The c_header format gives a clean .h with
all the prototypes — pasteable into IDA / Ghidra as a type library.
**Why:** Work handover between agents: "here are the decompiled
signatures I trust for this binary — import them next time".
**IDA:** `api_analysis.py::export_funcs`.
**Ghidra API:** enumerate functions, decompile each (or just read
signatures), format.
**Complexity:** M.

## Tier 4 — Optional / nice-to-have

### [ ] find_callers_of_import (Synapse)
**What:** Bulk "which functions call VirtualAlloc?" query. Today
the agent has to (1) find the import address via
`list_imports(query="VirtualAlloc")`, (2) call `list_xrefs(addr)`.
**Why:** One call instead of two. Saves 1-2 round-trips per
suspicious API.
**IDA:** `api_analysis.py::find_callers_of_import`.
**Ghidra API:** external symbol lookup + xref enumeration.
**Complexity:** S.

### [ ] construct / cstruct (Synapse)
**What:** Parse binary data at an address using a C struct
definition, or define a new struct in the type library. Useful for
import tables, resource headers, packed records.
**Why:** Some binaries (e.g. PE-packers) read custom structures from
data sections; an agent needs to be able to "treat this 64-byte
blob as a struct X".
**IDA:** `api_construct.py`, `api_cstruct.py`.
**Ghidra API:** `DataTypeManager.addDataType()`,
`Memory.getBytes(addr, size)` + manual parsing.
**Complexity:** M (the parsing layer is a port from construct/cstruct).

### [ ] find_vtable_callers (Synapse)
**What:** Find vtable dispatch sites — calls through a vtable at a
known offset. Critical for C++ reverse engineering.
**Why:** Spot the pattern `mov rax, [rcx]; call [rax+0x40]` and
trace which method is being called.
**IDA:** `api_analysis.py::find_vtable_callers`.
**Ghidra API:** similar to insn_query but with vtable-aware operand
pattern matching.
**Complexity:** M.

### [ ] find_render_loop (Synapse)
**What:** Detect D3D/DXGI/D3D9/D3D12 frame-presentation call sites in
a binary. DXGI Present at vtable slot 8 = offset 0x40.
**Why:** Reverse-engineering a game? This is your entry point.
**IDA:** `api_analysis.py::find_render_loop`.
**Ghidra API:** scan all `call [reg+offset]` with known
IDXGISwapChain / IDirect3DDevice9 offsets.
**Complexity:** S.

### [ ] filetype (Synapse `api_filetype.py`)
**What:** Identify the file type of a buffer (any binary blob) by
magic-byte signature. Distinct from `lief_info` which is for
PE/ELF/Mach-O — this works on any file.
**Why:** "I dragged in some random file from disk, what is it?"
**IDA:** `api_filetype.py`.
**Ghidra API:** Ghidra has `FileBytes` and loaders, but for raw buffer
identification, use `puremagic` (already a dep) or a custom table.
**Complexity:** S.

## See also

Tools that exist in pyghidra-mcp but might benefit from docstring
upgrades / parity fixes with Synapse:

- [ ] survey_binary_fast / survey_binary_full — verify docstring
  is as informative as the Synapse tool_description (it should
  be visible to the model via tools/list).
- [ ] decompile_function — verify the warning-passthrough + error
  classifier (MERR_*) from Synapse. pyghidra-mcp's
  `decompile_function` already returns error info but doesn't
  classify the failure category.
- [ ] disassemble — Synapse has separate `disasm` (single function,
  paginated) and `disasm_batch`. pyghidra-mcp has `disassemble`
  only. Add `disassemble_batch`.
- [ ] list_xrefs — Synapse has `xrefs_to` (single addr),
  `xref_query` (filtered + paginated), and `xrefs_to_field`
  (struct field). pyghidra-mcp has only `list_xrefs`. Add
  `list_xrefs_query` (the filtered version).
- [ ] search_code — already in pyghidra-mcp as semantic + literal;
  verify it covers Synapse's `search_code` (limit, offset, full-code
  toggle, preview length, similarity threshold).
- [ ] search_symbols_by_name — verify the regex + namespace
  semantics match Synapse's `list_funcs` / `find_funcs`.

## Reference: Synapse tools NOT ported (intentional)

These exist in Synapse but we are **not** porting them because they
depend on infrastructure we don't have:

- Anything from `api_angr.py` / `api_triton.py` / `api_unicorn.py` —
  dynamic symbolic execution / concrete emulation. Heavy. Not
  needed for static triage. **May add later** if/when an agent
  needs to solve a crackme.
- `api_networkx.py` / `api_numpy.py` — used internally by other
  tools (find_similar_functions, etc). Port them as a dependency
  when we port the consumers.
- `api_lief.py` (200KB) — comprehensive PE/ELF/Mach-O parsing.
  pyghidra-mcp has lighter metadata via `program.getMetadata()`.
  **Port the high-value subset** (imphash, sections, debug dir,
  imports-by-name) when an agent needs them.
- `api_types.py` (128KB) — `declare_type` / `infer_types` /
  `apply_type_batch`. Heavy. Useful for batch retyping after a
  mass-analysis pass. **Defer.**

## Workflow

When you (or another agent) pick a tool from this list:

1. Create a feature/tools-expansion branch (or work on this one if
   it's the current branch — see AGENTS.md for the workflow).
2. Add an `api_<name>.py` next to `api_survey.py` mirroring Synapse's
   module structure but adapted to Ghidra's APIs.
3. Add a `GhidraTools.<name>()` wrapper in `tools.py`.
4. Add an async handler in `mcp_tools.py` — must `await
   get_executor().submit(program_info, fn)` for any Ghidra call.
5. Add Pydantic request/response models in `models.py`.
6. Register in `server.py::register_common_tools()`.
7. Add unit tests in `tests/unit/` (mock-based, executor mocking).
8. Add integration tests in `tests/integration/` (real Ghidra,
   real binary).
9. Commit on `feature/tools-expansion`. Don't touch
   `feature/concurrency-safety`.

Reference: `api_survey.py` + `tests/unit/test_survey_binary.py` +
`tests/integration/test_survey_binary.py` is the reference
implementation of this pattern — copy its structure.
