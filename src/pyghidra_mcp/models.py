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
    callees: list[str] | None = None
    referenced_strings: list[str] | None = None
    xrefs: list["CrossReferenceInfo"] | None = None


class ProgramBasicInfo(BaseModel):
    name: str
    analysis_complete: bool


class ProgramBasicInfos(BaseModel):
    programs: list[ProgramBasicInfo]


class ProgramInfo(BaseModel):
    name: str
    file_path: str | None = None
    load_time: float | None = None
    analysis_complete: bool
    metadata: dict
    code_indexed: bool
    strings_indexed: bool


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
    requested_path: str
    queued_count: int
    queued_paths: list[str]
    skipped_count: int
    skipped: list[SkippedImport]
    message: str


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
