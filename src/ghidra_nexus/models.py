from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class DecompiledFunction(BaseModel):
    name: str
    code: str
    signature: str | None = None
    error: str | None = None
    decompiler_status: str | None = Field(
        None,
        description=(
            "decompiled (success), decompiled_empty (no C output but no error), "
            "decompiler_error (Ghidra decompiler failed)"
        ),
    )
    # New (Phase 0.5): explicit failure classification. Stable string the
    # agent branches on; one of ToolErrorCode.* values or None on success.
    error_code: str | None = Field(
        None,
        description=(
            "On decompile failure, one of the stable ToolErrorCode values: "
            "encrypted_bytes, function_too_small, no_license, unsupported_isa, "
            "decompile_failed. None when decompiler_status='decompiled' or "
            "'decompiled_empty'."
        ),
    )
    hint: str | None = Field(
        None,
        description="One-sentence next step on decompile failure.",
    )
    callees: list[str] | None = None
    referenced_strings: list[str] | None = None
    xrefs: list["CrossReferenceInfo"] | None = None


class ProgramBasicInfo(BaseModel):
    name: str
    analysis_complete: bool


class ProgramBasicInfos(BaseModel):
    programs: list[ProgramBasicInfo]


class AnalysisState(str, Enum):
    """Lifecycle stage of a Ghidra binary's analysis.

    Reported by ``analysis_status`` and ``import_binary``. Agents poll until
    ``analysis_complete == "complete"`` (or until a state they care about
    transitions).
    """

    QUEUED = "queued"                      # import_binary returned; not loaded yet
    LOADING = "loading"                    # Ghidra is reading file bytes
    ANALYZING_FUNCTIONS = "analyzing_functions"
    ANALYZING_DATA = "analyzing_data"
    COMPLETE = "complete"
    FAILED = "failed"


class EntropySummary(str, Enum):
    """Top-level entropy profile across the binary's sections."""

    ENCRYPTED = "encrypted"        # any section >= 7.0 entropy
    COMPRESSED = "compressed"      # any section 5.5-7.0 entropy, none above
    NORMAL = "normal"              # all sections < 5.5 entropy
    MIXED = "mixed"                # some normal + some encrypted/compressed


class ProgramInfo(BaseModel):
    name: str
    file_path: str | None = None
    load_time: float | None = None
    analysis_complete: bool
    metadata: dict
    code_indexed: bool
    strings_indexed: bool

    # --- Phase 0.5 additions ---
    analysis_state: str = "complete"  # AnalysisState value
    function_count: int = 0
    sha256: str | None = None
    entropy_summary: str = "unknown"  # EntropySummary value or "unknown"
    project_path: str | None = None
    nexus_data_dir: str | None = None
    idb_path: str | None = None
    path_exists: bool | None = Field(
        None,
        description="True when file_path / idb_path was checked and exists on disk.",
    )
    recommended_tools: list[str] = Field(
        default_factory=list,
        description=(
            "Tools the agent should call next given this binary's state. e.g. "
            "['survey_binary_fast', 'section_health'] for fresh import."
        ),
    )


class AnalysisStatusResult(BaseModel):
    """Top-level ``analysis_status`` response.

    Wraps a list of :class:`ProgramInfo` plus server-level path warnings. This
    is THE source of truth for "what does the project look like right now" —
    agents should poll this rather than rely on free-text error responses.
    """

    binaries: list[ProgramInfo]
    path_warnings: list[str] = Field(
        default_factory=list,
        description=(
            "Server-level warnings about project_path writability. Surfaces UAC-locked "
            "directories on Windows before IDB writes silently fail."
        ),
    )
    server_version: str = ""


class ProgramInfos(BaseModel):
    programs: list[ProgramInfo]


class OpenProgramInfo(BaseModel):
    name: str
    path: str
    current: bool
    analysis_complete: bool


class OpenProgramInfos(BaseModel):
    programs: list[OpenProgramInfo]


class SkippedImport(BaseModel):
    path: str
    reason: str


class ImportRequestResult(BaseModel):
    """Result of ``import_binary``.

    Phase 0.5 additions:
        - ``task_id`` lets the agent poll ``analysis_status`` deterministically.
        - ``binary_name`` is the canonical name the agent uses for every other
          tool call (we resolve paths to canonical names once at import time).
        - ``analysis_state`` is the lifecycle stage: ``queued`` | ``loading`` |
          ``analyzing_functions`` | ``analyzing_data`` | ``complete`` | ``failed``.
        - ``function_count`` is the live function count at this instant. Stays
          0 until Ghidra finds functions.
        - ``idb_path`` is the absolute path to the saved IDB; the agent can
          validate ``os.path.exists`` against it.
    """

    requested_path: str
    queued_count: int
    queued_paths: list[str]
    skipped_count: int
    skipped: list[SkippedImport]
    message: str

    task_id: str | None = None
    binary_name: str | None = None
    analysis_state: str = "queued"
    function_count: int = 0
    idb_path: str | None = None
    project_path: str | None = None
    nexus_data_dir: str | None = None


class SectionClassification(str, Enum):
    """Agent-friendly classification of a memory section based on entropy + perms."""

    CODE = "code"
    DATA = "data"
    COMPRESSED = "compressed"
    ENCRYPTED = "encrypted"
    UNKNOWN = "unknown"


class SectionRecommendation(str, Enum):
    """Action the agent should take for a section."""

    ANALYZE = "analyze"            # Code or low-entropy data — normal flow.
    SKIP = "skip"                  # Skip — likely noise or irrelevant.
    DECOMPRESS = "decompress"      # Compressed — run a decompressor pass first.
    DUMP_RUNTIME = "dump_runtime"  # Encrypted at rest — need runtime dump.


def classify_entropy(entropy: float, size_bytes: int) -> SectionClassification:
    """Map Shannon entropy + size to a classification (no permission info).

    Prefer :func:`ghidra_nexus.section_entropy.classify_section` when executability
    is known — that path also returns recommendation + reason. This helper remains
    for lightweight call sites that only need the class label.
    """
    if size_bytes < 16:
        return SectionClassification.UNKNOWN
    if entropy >= 7.0:
        return SectionClassification.ENCRYPTED
    if entropy >= 5.5:
        return SectionClassification.COMPRESSED
    return SectionClassification.CODE


def recommendation_for(classification: SectionClassification) -> SectionRecommendation:
    """Map classification → recommendation. Prefer ``section_entropy.classify_section``."""
    if classification == SectionClassification.ENCRYPTED:
        return SectionRecommendation.DUMP_RUNTIME
    if classification == SectionClassification.COMPRESSED:
        return SectionRecommendation.DECOMPRESS
    if classification == SectionClassification.DATA:
        return SectionRecommendation.SKIP
    return SectionRecommendation.ANALYZE


class SectionHealth(BaseModel):
    """One row in the ``section_health`` MCP response.

    This is the dedicated-tool surface; the survey path reuses the same fields
    embedded in ``SurveySegmentInfo``.
    """

    name: str
    start: str
    end: str
    size_bytes: int
    entropy: float = Field(..., description="Shannon entropy in bits/byte (0..8).")
    classification: SectionClassification
    recommendation: SectionRecommendation
    reason: str = Field(..., description="Human-readable why this classification was chosen.")
    permissions: str = Field("---", description="rwx triplet, e.g. 'r-x', 'rw-'.")


class SurveySegmentInfo(BaseModel):
    """Per-section view in survey_binary. Phase 0.5 adds entropy + recommendation.

    Existing fields preserved for backward compat; new fields are optional so
    older clients don't see ``None`` noise.
    """

    name: str
    start: str
    end: str
    size: str
    permissions: str
    entropy: float | None = None
    classification: SectionClassification | None = None
    recommendation: SectionRecommendation | None = None
    reason: str | None = Field(
        None,
        description="Human-readable explanation for the classification.",
    )


class SaveRequestResult(BaseModel):
    model_config = ConfigDict(extra="allow")


class GotoResponse(BaseModel):
    binary_name: str
    address: str
    success: bool


class GuiContextResponse(BaseModel):
    active_program: str | None = None
    active_provider: str | None = None
    active_address: str | None = None
    active_function: str | None = None
    selection: str | None = None
    location_type: str | None = None


class RenameResponse(BaseModel):
    binary_name: str
    address: str
    old_name: str
    new_name: str


class VariableRenameResponse(BaseModel):
    binary_name: str
    function_name: str
    function_address: str
    variable_kind: str
    old_name: str
    new_name: str


class VariableTypeResponse(BaseModel):
    binary_name: str
    function_name: str
    function_address: str
    variable_kind: str
    variable_name: str
    old_type: str
    new_type: str


class FunctionPrototypeResponse(BaseModel):
    binary_name: str
    function_name: str
    function_address: str
    old_prototype: str
    new_prototype: str


class CommentResponse(BaseModel):
    binary_name: str
    address: str
    comment: str
    comment_type: str


class ExportInfo(BaseModel):
    name: str
    address: str


class ExportInfos(BaseModel):
    exports: list[ExportInfo]


class ImportInfo(BaseModel):
    name: str
    library: str


class ImportInfos(BaseModel):
    imports: list[ImportInfo]


class CrossReferenceInfo(BaseModel):
    function_name: str | None = None
    from_address: str
    to_address: str
    type: str


class CrossReferenceInfos(BaseModel):
    target: str | None = None
    cross_references: list[CrossReferenceInfo]
    error: str | None = None
    # Phase 0.5.1: typed failure fields (parallel to DecompiledFunction).
    error_code: str | None = None
    hint: str | None = None


# Resolve forward reference for DecompiledFunction.xrefs
DecompiledFunction.model_rebuild()


class SymbolInfo(BaseModel):
    name: str
    address: str
    type: str
    namespace: str
    source: str
    refcount: int
    external: bool
    is_thunk: bool = False
    thunk_target: str | None = None


class SymbolSearchResults(BaseModel):
    symbols: list[SymbolInfo]


class SearchMode(str, Enum):
    """Search mode for code search."""

    SEMANTIC = "semantic"  # Vector similarity search
    LITERAL = "literal"  # Exact string match ($contains)


class CodeSearchResult(BaseModel):
    function_name: str
    code: str
    similarity: float
    search_mode: SearchMode
    preview: str | None = None


class CodeSearchResults(BaseModel):
    results: list[CodeSearchResult]
    query: str
    search_mode: SearchMode
    returned_count: int
    offset: int
    limit: int
    literal_total: int = Field(..., description="total literal matches")
    semantic_total: int = Field(..., description="estimated semantic matches")
    total_functions: int


class StringInfo(BaseModel):
    value: str
    address: str


class StringDroppedNote(BaseModel):
    count: int
    message: str


class StringSearchResult(StringInfo):
    similarity: float


class StringSearchResults(BaseModel):
    strings: list[StringSearchResult]
    dropped_note: StringDroppedNote | None = Field(
        None,
        description="Present when some string values could not be read (corrupted data)",
    )


class BytesReadResult(BaseModel):
    address: str
    size: int
    data: str = Field(..., description="hex string")


class DisassembleResult(BaseModel):
    address: str
    count: int
    listing: str = Field(
        ...,
        description=(
            "Newline-delimited disassembly listing. Each line is single-space separated: "
            "address, optional raw bytes (hex, when include_bytes=True), mnemonic, operands."
        ),
    )


class CallGraphDirection(str, Enum):
    """Represents the direction of the call graph."""

    CALLING = "calling"
    CALLED = "called"


class CallGraphDisplayType(str, Enum):
    """Represents the display type of the call graph."""

    FLOW = "flow"
    FLOW_ENDS = "flow_ends"
    MIND = "mind"


class CallGraphResult(BaseModel):
    function_name: str
    direction: CallGraphDirection
    display_type: CallGraphDisplayType
    graph: str = Field(..., description="MermaidJS graph string")
    mermaid_url: str


class SurveyMetadata(BaseModel):
    path: str
    module: str
    arch: str
    base_address: str
    image_size: str
    md5: str
    sha256: str


class SurveySegmentInfo(BaseModel):
    name: str
    start: str
    end: str
    size: str
    permissions: str


class SurveyEntrypoint(BaseModel):
    addr: str
    name: str


class SurveyStatistics(BaseModel):
    total_functions: int
    named_functions: int
    library_functions: int
    unnamed_functions: int
    thunk_functions: int
    total_strings: int
    total_segments: int


class SurveyInterestingString(BaseModel):
    addr: str
    string: str
    xref_count: int


class SurveyInterestingFunction(BaseModel):
    addr: str
    name: str
    size: int
    xref_count: int
    callee_count: int
    type: str


class SurveyImportEntry(BaseModel):
    addr: str
    name: str
    library: str


class SurveyImportsByCategory(BaseModel):
    crypto: list[SurveyImportEntry] = Field(default_factory=list)
    network: list[SurveyImportEntry] = Field(default_factory=list)
    file_io: list[SurveyImportEntry] = Field(default_factory=list)
    process: list[SurveyImportEntry] = Field(default_factory=list)
    registry: list[SurveyImportEntry] = Field(default_factory=list)
    other: list[SurveyImportEntry] = Field(default_factory=list)


class SurveyCallGraphSummary(BaseModel):
    total_edges: int
    max_depth_estimate: int | None = None
    root_functions: list[str] = Field(default_factory=list)
    leaf_functions_count: int = 0


class SurveyRecommendedTools(BaseModel):
    interesting_strings: str
    interesting_functions: str
    imports_by_category: str
    call_graph_summary: str
    overall: str


class SurveyBinaryResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    ok: bool
    mode: str = Field(
        "full",
        description=(
            "Which survey path produced this result: 'fast' (pre-analysis, "
            "returned in milliseconds from raw-import data) or 'full' (post "
            "Ghidra auto-analysis, with xref-ranked top-15s, classified "
            "functions, and call-graph topology). Helps the agent know "
            "whether the numbers can be trusted for triage."
        ),
    )
    metadata: SurveyMetadata
    statistics: SurveyStatistics
    segments: list[SurveySegmentInfo]
    entrypoints: list[SurveyEntrypoint]
    interesting_strings: list[SurveyInterestingString] | None = None
    interesting_functions: list[SurveyInterestingFunction] | None = None
    imports_by_category: SurveyImportsByCategory | None = None
    call_graph_summary: SurveyCallGraphSummary | None = None
    recommended_tools: SurveyRecommendedTools | None = None
    note: str | None = None
    error: str | None = None
