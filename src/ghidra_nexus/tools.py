"""
Comprehensive tool implementations for ghidra-nexus.
"""

import functools
import logging
import re
import typing
from contextlib import contextmanager

from ghidrecomp.callgraph import gen_callgraph
from jpype import JByte

from ghidra_nexus.errors import classify_decompile_failure, make_tool_error
from ghidra_nexus.models import (
    BytesReadResult,
    CallGraphDirection,
    CallGraphDisplayType,
    CallGraphResult,
    CallSiteAnalysisResult,
    CallSiteInfo,
    CodeSearchResult,
    CodeSearchResults,
    CrossReferenceInfo,
    DecompiledFunction,
    DisassembleResult,
    ExportInfo,
    ImportInfo,
    SearchMode,
    SectionHealth,
    StringInfo,
    StringSearchResult,
    SurveyBinaryResult,
    SymbolInfo,
    VerifyPortCheck,
    VerifyPortResult,
)
from ghidra_nexus.section_entropy import classify_section, shannon_entropy

_REGEX_META = re.compile(r"[\\^$.|?*+(){}\[\]]")

if typing.TYPE_CHECKING:
    from ghidra.app.decompiler import DecompileResults
    from ghidra.program.model.listing import Function
    from ghidra.program.model.symbol import Symbol

    from .context import ProgramInfo

logger = logging.getLogger(__name__)


@contextmanager
def ghidra_transaction(program, description: str):
    tx_id = program.startTransaction(description)
    committed = False
    try:
        yield
        committed = True
    finally:
        program.endTransaction(tx_id, committed)


def handle_exceptions(func):
    """Decorator to handle exceptions in tool methods"""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {e!s}")
            raise

    return wrapper


class GhidraTools:
    """Comprehensive tool handler for Ghidra MCP tools"""

    def __init__(self, program_info: "ProgramInfo"):
        """Initialize with a Ghidra ProgramInfo object"""
        self.program_info = program_info
        self.program = program_info.program
        self.decompiler_pool = program_info.decompiler_pool

    def _get_filename(self, func: "Function"):
        max_path_len = 50
        return f"{func.getSymbol().getName(True)[:max_path_len]}-{func.entryPoint}"

    def _resolve_function_variable(
        self,
        function_name_or_address: str,
        variable_name: str,
    ) -> tuple["Function", str, typing.Any]:
        func = self.find_function(function_name_or_address)
        function_name = str(func.getName())

        matches: list[tuple[str, typing.Any]] = []
        for param in func.getParameters():
            if str(param.getName()) == variable_name:
                matches.append(("parameter", param))
        for local in func.getLocalVariables():
            if str(local.getName()) == variable_name:
                matches.append(("local", local))

        if not matches:
            raise ValueError(f"Variable '{variable_name}' not found in function '{function_name}'.")
        if len(matches) > 1:
            kinds = ", ".join(kind for kind, _ in matches)
            raise ValueError(
                f"Ambiguous variable '{variable_name}' in function '{function_name}' ({kinds})."
            )

        variable_kind, variable = matches[0]
        return func, variable_kind, variable

    def _parse_data_type(self, type_name: str):
        from ghidra.util.data import DataTypeParser  # type: ignore
        from ghidra.util.data.DataTypeParser import AllowedDataTypes  # type: ignore

        dtm = self.program.getDataTypeManager()
        parser = DataTypeParser(dtm, dtm, typing.cast(typing.Any, None), AllowedDataTypes.DYNAMIC)
        return parser.parse(type_name)

    def _lookup_functions(
        self,
        name_or_address: str,
        partial: bool = False,
        include_externals: bool = True,
    ) -> list["Function"]:
        """
        Resolve functions by name or address.
        Returns a flat list of unique Function objects.
        Exact matches are always returned first; partial (substring) matches
        are appended only when ``partial`` is enabled.
        """
        af = self.program.getAddressFactory()
        fm = self.program.getFunctionManager()

        # Try interpreting as an address first
        try:
            addr = af.getAddress(name_or_address)
            if addr:
                func = fm.getFunctionAt(addr)
                if func is None:
                    func = fm.getFunctionContaining(addr)
                if func:
                    return [func]
        except (Exception) as e:
            from ghidra.program.model.address import AddressFormatException
            from java.lang import IllegalArgumentException

            if not isinstance(e, (IllegalArgumentException, AddressFormatException)):
                raise

        name_lc = name_or_address.lower()
        functions = self.get_all_functions(include_externals=include_externals)
        seen: set = set()
        matches: list[Function] = []

        for f in functions:
            key = f.getEntryPoint()
            if key not in seen and name_lc == f.getSymbol().getName(True).lower():
                seen.add(key)
                matches.append(f)

        if partial:
            for f in functions:
                key = f.getEntryPoint()
                if key not in seen and name_lc in f.getSymbol().getName(True).lower():
                    seen.add(key)
                    matches.append(f)

        return matches

    @handle_exceptions
    def find_function(
        self,
        name_or_address: str,
        include_externals: bool = True,
    ) -> "Function":
        """
        Resolve a single function by name or address (exact match only).
        Raises if ambiguous or not found.
        """
        matches = self._lookup_functions(
            name_or_address, partial=False, include_externals=include_externals
        )

        if len(matches) == 1:
            return matches[0]
        elif len(matches) > 1:
            suggestions = [
                f"{f.getSymbol().getName(True)}({f.getSignature()}) @ {f.getEntryPoint()}"
                for f in matches
            ]
            raise ValueError(
                f"Ambiguous match for '{name_or_address}'. Did you mean one of these: "
                + ", ".join(suggestions)
            )
        else:
            raise ValueError(f"Function or symbol '{name_or_address}' not found.")

    @handle_exceptions
    def find_functions(
        self,
        name_or_address: str,
        include_externals: bool = True,
    ) -> list["Function"]:
        """
        Return all functions that match name_or_address (exact or partial).
        Never raises; returns empty list if none.
        """
        return self._lookup_functions(
            name_or_address, partial=True, include_externals=include_externals
        )

    def _lookup_symbols(
        self,
        name_or_address: str,
        *,
        partial: bool = False,
        dynamic: bool = False,
    ) -> list["Symbol"]:
        """
        Resolve symbols by name or address.
        Returns a single flat list of unique Symbol objects.
        Exact matches are always included; partial (substring) and dynamic
        matches are added only when their respective flags are enabled.
        """
        st = self.program.getSymbolTable()
        af = self.program.getAddressFactory()

        # Try interpreting as an address first
        try:
            addr = af.getAddress(name_or_address)
            if addr:
                addr_symbols = st.getSymbols(addr)
                if addr_symbols:
                    return list(addr_symbols)
        except (Exception) as e:
            from ghidra.program.model.address import AddressFormatException
            from java.lang import IllegalArgumentException

            if not isinstance(e, (IllegalArgumentException, AddressFormatException)):
                raise

        name_lc = name_or_address.lower()
        matches: set[Symbol] = set()

        # Base symbol set (externals only once)
        base_symbols = self.get_all_symbols(include_externals=True)

        # Exact match (always included)
        matches.update(s for s in base_symbols if name_lc == s.getName(True).lower())

        # Partial match
        if partial:
            matches.update(s for s in base_symbols if name_lc in s.getName(True).lower())

        # Dynamic match (requires second scan)
        if dynamic:
            dyn_symbols = self.get_all_symbols(include_externals=True, include_dynamic=True)
            matches.update(s for s in dyn_symbols if name_lc in s.getName(True).lower())

        return list(matches)

    @handle_exceptions
    def find_symbols(self, name_or_address: str) -> list["Symbol"]:
        """
        Return all symbols that match name_or_address (exact or partial).
        Never raises; returns empty list if none.
        """
        return self._lookup_symbols(name_or_address, partial=True)

    @handle_exceptions
    def find_symbol(self, name_or_address: str) -> "Symbol":
        """
        Resolve a single symbol by name or address (exact match only).
        Raises if ambiguous or not found.
        """
        matches = self._lookup_symbols(name_or_address, partial=False)

        if len(matches) == 1:
            return matches[0]
        elif len(matches) > 1:
            suggestions = [f"{s.getName(True)} @ {s.getAddress()}" for s in matches]
            raise ValueError(
                f"Ambiguous match for '{name_or_address}'. Did you mean one of these: "
                + ", ".join(suggestions)
            )
        else:
            raise ValueError(f"Symbol '{name_or_address}' not found.")

    @handle_exceptions
    def decompile_function_by_name_or_addr(
        self, name_or_address: str, timeout: int = 0
    ) -> DecompiledFunction:
        """Finds and decompiles a function in a specified binary and returns its pseudo-C code."""

        func = self.find_function(name_or_address)
        return self.decompile_function(func, timeout=timeout)

    def decompile_function(self, func: "Function", timeout: int = 0) -> DecompiledFunction:
        """Decompiles a function in a specified binary and returns its pseudo-C code.

        Phase 0.5: on failure, sets ``error_code`` (stable string from
        :class:`ToolErrorCode`) and ``hint`` so the agent can branch on it
        without parsing free-text error messages. See ``errors.py``.
        """
        from ghidra.util.task import ConsoleTaskMonitor

        monitor = ConsoleTaskMonitor()
        with self.decompiler_pool.acquire() as decompiler:
            result: DecompileResults = decompiler.decompileFunction(func, timeout, monitor)
        error_code: str | None = None
        hint: str | None = None
        error_text: str | None = None
        if "" == result.getErrorMessage():
            decompiled = result.getDecompiledFunction()
            if decompiled is None:
                code = ""
                sig = None
                status = "decompiled_empty"
            else:
                code = decompiled.getC().replace("\r\n", "\n")
                sig = decompiled.getSignature()
                status = "decompiled"
        else:
            # Never put free-text error into `code` — agents treat that as pseudo-C.
            error_msg = result.getErrorMessage()
            code = ""
            sig = None
            status = "decompiler_error"
            error_text = error_msg
            code_enum = classify_decompile_failure(error_msg)
            error_code = code_enum.value
            err = make_tool_error(
                code_enum,
                error_msg,
                binary_name=self.program.getName() if self.program else None,
            )
            hint = err.get("hint")
        return DecompiledFunction(
            name=self._get_filename(func),
            code=code,
            signature=sig,
            error=error_text,
            decompiler_status=status,
            error_code=error_code,
            hint=hint,
        )

    @handle_exceptions
    def get_all_functions(self, include_externals=False) -> list["Function"]:
        """
        Gets all functions within a binary.
        Returns a python list that doesn't need to be re-intialized
        """

        funcs = set()
        fm = self.program.getFunctionManager()
        functions = fm.getFunctions(True)
        for func in functions:
            func: Function
            if not include_externals and func.isExternal():
                continue
            if not include_externals and func.thunk:
                continue
            funcs.add(func)
        return list(funcs)

    @handle_exceptions
    def get_all_symbols(
        self, include_externals: bool = False, include_dynamic=False
    ) -> list["Symbol"]:
        """
        Gets all symbols within a binary.
        Returns a python list that doesn't need to be re-initialized.
        """

        symbols = set()
        from ghidra.program.model.symbol import SymbolTable

        st: SymbolTable = self.program.getSymbolTable()
        all_symbols = st.getAllSymbols(include_dynamic)

        for sym in all_symbols:
            sym: Symbol
            if not include_externals and sym.isExternal():
                continue
            symbols.add(sym)

        return list(symbols)

    @handle_exceptions
    def get_all_strings(self) -> tuple[list[StringInfo], int]:
        """Gets all defined strings for a binary.
        Returns (strings, dropped_count) where dropped_count is the number
        of string values that could not be read due to corruption.
        """
        try:
            from ghidra.program.util import DefinedStringIterator  # type: ignore

            data_iterator = DefinedStringIterator.forProgram(self.program)
        except ImportError:
            from ghidra.program.util import DefinedDataIterator

            data_iterator = DefinedDataIterator.definedStrings(self.program)

        strings = []
        dropped = 0
        for data in data_iterator:
            try:
                string_value = data.getValue()
                strings.append(StringInfo(value=str(string_value), address=str(data.getAddress())))
            except Exception as e:
                dropped += 1
                logger.debug(f"Could not get string value from data at {data.getAddress()}: {e}")

        return strings, dropped

    @handle_exceptions
    def survey_binary(self, detail_level: str = "standard") -> SurveyBinaryResult:
        """Single-call binary triage snapshot — alias for :meth:`survey_binary_full`.

        Kept for backward compatibility. Prefer :meth:`survey_binary_fast` when
        you need a quick triage in milliseconds (pre-analysis) and
        :meth:`survey_binary_full` when you can wait for the complete
        Ghidra auto-analysis.
        """
        return self.survey_binary_full(detail_level=detail_level)

    @handle_exceptions
    def survey_binary_fast(self) -> SurveyBinaryResult:
        """Pre-analysis triage snapshot — returns in milliseconds.

        Use this for quick first-look triage without waiting for Ghidra's
        full auto-analysis (which can take 5-10 minutes on a fresh binary
        due to PDB download + Decompiler analyzers).

        Returns file metadata, segment layout, entry points, statistics,
        imports grouped by category, top functions ranked by *body size*
        (NOT xrefs — xrefs are not computed yet), and a length-sorted
        slice of defined strings. The result's ``mode`` field is
        ``"fast"`` and the ``note`` field is set to
        ``"pre-analysis: ..."`` so the agent can tell at a glance.

        This tool does NOT wait for ``analysis_status()`` to report
        complete. It is the right choice when an agent just imported a
        binary and wants to know "is this interesting enough to decompile?"
        before committing to a 5-10 minute analysis wait.
        """
        from ghidra_nexus import api_survey

        raw = api_survey.survey_binary_fast(self.program)
        return SurveyBinaryResult.model_validate(raw)

    @handle_exceptions
    def survey_binary_full(
        self, detail_level: str = "standard"
    ) -> SurveyBinaryResult:
        """Post-analysis triage snapshot — waits for full Ghidra analysis.

        Returns file metadata, segment layout, entry points, statistics,
        top 15 strings ranked by xref count, top 15 functions ranked by
        xref count (each classified as ``thunk`` / ``wrapper`` / ``leaf`` /
        ``dispatcher`` / ``complex``), imports grouped by category, and a
        call-graph summary with max-depth BFS estimate.

        The result's ``mode`` field is ``"full"``.

        This tool refuses to run while Ghidra auto-analysis is still in
        progress — call :func:`analysis_status` first to check, or use
        :meth:`survey_binary_fast` to get a pre-analysis snapshot instead.

        Parameters
        ----------
        detail_level
            ``"standard"`` returns the full payload above. ``"minimal"``
            returns only metadata, statistics, segments, and entrypoints
            — use for very large binaries where the full payload would
            block the executor thread.
        """
        from ghidra_nexus import api_survey

        if detail_level not in ("standard", "minimal"):
            raise ValueError("detail_level must be 'standard' or 'minimal'")

        raw = api_survey.survey_binary(self.program, detail_level=detail_level)
        return SurveyBinaryResult.model_validate(raw)

    @handle_exceptions
    def section_health(self, max_size_bytes: int = 4 * 1024 * 1024) -> list[SectionHealth]:
        """Per-section entropy + classification + agent recommendation.

        Computes Shannon entropy for each initialised memory block (subsampled
        to ``max_size_bytes`` for huge blocks like Affinity's 309 MB ``.text``)
        and returns a flat list of :class:`SectionHealth`. Cheap to call on
        any binary.

        Use this as the **first** call after ``analysis_status`` reports
        complete: it surfaces encrypted/packed sections in one shot, saving
        a ``Get-ChildItem`` round trip and three ``decompile_function`` calls
        that were going to fail anyway.
        """
        blocks = list(self.program.getMemory().getBlocks())
        memory = self.program.getMemory()
        results: list[SectionHealth] = []

        for block in blocks:
            try:
                name = block.getName() or ""
                start = block.getStart()
                end = block.getEnd()
                size = int(block.getSize())
                try:
                    is_r = bool(block.isRead())
                except Exception:
                    is_r = False
                try:
                    is_w = bool(block.isWrite())
                except Exception:
                    is_w = False
                try:
                    is_x = bool(block.isExecute())
                except Exception:
                    is_x = False
                perms = ("r" if is_r else "-") + ("w" if is_w else "-") + ("x" if is_x else "-")

                entropy_val: float | None = None
                sample = min(size, max_size_bytes)
                if sample > 0:
                    try:
                        raw = memory.getBytes(start, sample)
                        if raw is not None and len(raw) > 0:
                            entropy_val = shannon_entropy(bytes(raw))
                    except Exception:
                        entropy_val = None

                classification, recommendation, reason = classify_section(
                    entropy_val if entropy_val is not None else 0.0,
                    size,
                    is_executable=is_x,
                )

                results.append(
                    SectionHealth(
                        name=name,
                        start=str(start),
                        end=str(end),
                        size_bytes=size,
                        entropy=entropy_val if entropy_val is not None else 0.0,
                        classification=classification,
                        recommendation=recommendation,
                        reason=reason,
                        permissions=perms,
                    )
                )
            except Exception:
                continue
        return results

    @staticmethod
    def _matches_query(query: str, symbol_name: str) -> bool:
        """Check if a symbol name matches a query (regex with substring fallback)."""
        try:
            return bool(re.search(query, symbol_name, re.IGNORECASE))
        except re.error:
            return query.lower() in symbol_name.lower()

    @classmethod
    def _symbol_matches_query(cls, query: str, symbol) -> bool:
        """Match against both simple and namespace-qualified symbol names."""
        names = {str(symbol.getName())}
        try:
            names.add(str(symbol.getName(True)))
        except TypeError:
            pass
        return any(cls._matches_query(query, name) for name in names)

    def _symbol_to_info(self, symbol, rm) -> SymbolInfo:
        """Convert a Ghidra Symbol to a SymbolInfo model."""
        ref_count = len(list(rm.getReferencesTo(symbol.getAddress())))
        is_thunk = False
        thunk_target = None

        try:
            func = self.program.getFunctionManager().getFunctionAt(symbol.getAddress())
        except Exception:
            func = None

        if func is not None:
            try:
                is_thunk = bool(func.isThunk())
            except Exception:
                is_thunk = False

            if is_thunk:
                try:
                    thunked = func.getThunkedFunction(True)
                except TypeError:
                    thunked = func.getThunkedFunction(False)
                except Exception:
                    thunked = None

                if thunked is not None:
                    thunk_target = (
                        f"{thunked.getSymbol().getName(True)} @ {thunked.getEntryPoint()}"
                    )

        return SymbolInfo(
            name=symbol.getName(),
            address=str(symbol.getAddress()),
            type=str(symbol.getSymbolType()),
            namespace=str(symbol.getParentNamespace()),
            source=str(symbol.getSource()),
            refcount=ref_count,
            external=symbol.isExternal(),
            is_thunk=is_thunk,
            thunk_target=thunk_target,
        )

    @classmethod
    def _symbol_sort_key(cls, query: str, symbol, info: SymbolInfo) -> tuple:
        names = {str(symbol.getName())}
        try:
            names.add(str(symbol.getName(True)))
        except TypeError:
            pass

        query_lc = query.lower()
        exact_name = any(name.lower() == query_lc for name in names)
        return (
            0 if exact_name else 1,
            1 if info.is_thunk else 0,
            1 if info.external else 0,
            -info.refcount,
            info.name.lower(),
            info.address,
        )

    @handle_exceptions
    def search_symbols_by_name(
        self, query: str, functions_only: bool = False, offset: int = 0, limit: int = 100
    ) -> list[SymbolInfo]:
        """Searches for symbols within a binary by name (supports regex).

        When functions_only=True, searches only function symbols (no labels/variables).
        """

        if not query:
            raise ValueError("Query string is required")

        rm = self.program.getReferenceManager()
        is_regex = bool(_REGEX_META.search(query))

        if functions_only:
            sources = self.get_all_functions(True) if is_regex else self.find_functions(query)
            symbols = (func.getSymbol() for func in sources)
        else:
            symbols = self.get_all_symbols(True) if is_regex else self.find_symbols(query)

        matches = []
        for sym in symbols:
            if not self._symbol_matches_query(query, sym):
                continue
            info = self._symbol_to_info(sym, rm)
            matches.append((sym, info))

        matches.sort(key=lambda item: self._symbol_sort_key(query, item[0], item[1]))
        results = [info for _, info in matches]
        return results[offset : limit + offset]

    @handle_exceptions
    def list_exports(
        self, query: str | None = None, offset: int = 0, limit: int = 25
    ) -> list[ExportInfo]:
        """Lists all exported functions and symbols from a specified binary."""
        exports = []
        symbols = self.program.getSymbolTable().getAllSymbols(True)
        for symbol in symbols:
            if symbol.isExternalEntryPoint():
                if query and not re.search(query, symbol.getName(), re.IGNORECASE):
                    continue
                exports.append(ExportInfo(name=symbol.getName(), address=str(symbol.getAddress())))
        return exports[offset : limit + offset]

    @handle_exceptions
    def list_imports(
        self, query: str | None = None, offset: int = 0, limit: int = 25
    ) -> list[ImportInfo]:
        """Lists all imported functions and symbols for a specified binary."""
        imports = []
        symbols = self.program.getSymbolTable().getExternalSymbols()
        for symbol in symbols:
            if query and not re.search(query, symbol.getName(), re.IGNORECASE):
                continue
            imports.append(
                ImportInfo(name=symbol.getName(), library=str(symbol.getParentNamespace()))
            )
        return imports[offset : limit + offset]

    @handle_exceptions
    def list_xrefs(self, name_or_address: str) -> list[CrossReferenceInfo]:
        """Finds and lists all cross-references (x-refs) to a given function, symbol,
        or address within a binary.
        """
        # Use the unified resolver
        sym: Symbol = self.find_symbol(name_or_address)
        addr = sym.getAddress()

        cross_references: list[CrossReferenceInfo] = []
        rm = self.program.getReferenceManager()
        references = rm.getReferencesTo(addr)

        for ref in references:
            from_func = self.program.getFunctionManager().getFunctionContaining(
                ref.getFromAddress()
            )
            cross_references.append(
                CrossReferenceInfo(
                    function_name=from_func.getName() if from_func else None,
                    from_address=str(ref.getFromAddress()),
                    to_address=str(ref.getToAddress()),
                    type=str(ref.getReferenceType()),
                )
            )
        return cross_references

    @handle_exceptions
    def get_callees(self, name_or_address: str) -> list[str]:
        """Get names of functions called by the given function."""
        from ghidra.util.task import ConsoleTaskMonitor

        func = self.find_function(name_or_address)
        monitor = ConsoleTaskMonitor()
        called = func.getCalledFunctions(monitor)
        return [f.getName() for f in called]

    @handle_exceptions
    def get_referenced_strings(self, name_or_address: str) -> list[str]:
        """Get string literals referenced within the given function's body."""
        from ghidra.program.model.data import AbstractStringDataType as StringDataType

        func = self.find_function(name_or_address)
        listing = self.program.getListing()
        strings: list[str] = []
        body = func.getBody()

        for insn in listing.getInstructions(body, True):
            for ref in insn.getReferencesFrom():
                data = listing.getDefinedDataAt(ref.getToAddress())
                if data is not None and isinstance(data.getDataType(), StringDataType):
                    val = data.getValue()
                    if val is not None:
                        strings.append(str(val))

        return strings

    def _search_code_literal(
        self,
        literal_results: typing.Any,
        limit: int,
        offset: int,
        include_full_code: bool,
        preview_length: int,
    ) -> list[CodeSearchResult]:
        search_results: list[CodeSearchResult] = []
        if literal_results and literal_results.get("documents"):
            # Apply offset and limit
            docs = literal_results["documents"] or []
            metadatas = literal_results["metadatas"] or []

            # Paginate
            start_idx = offset
            end_idx = offset + limit
            paginated_docs = docs[start_idx:end_idx]
            paginated_meta = metadatas[start_idx:end_idx] if metadatas else []

            for i, doc in enumerate(paginated_docs):
                metadata = paginated_meta[i] if i < len(paginated_meta) else {}
                code = doc
                preview = None

                if not include_full_code:
                    preview = code[:preview_length] + "..." if len(code) > preview_length else code
                    code = preview

                search_results.append(
                    CodeSearchResult(
                        function_name=str(
                            metadata.get("function_name", "unknown")
                            if isinstance(metadata, dict)
                            else "unknown"
                        ),
                        code=code,
                        similarity=1.0,  # Exact match
                        search_mode=SearchMode.LITERAL,
                        preview=preview,
                    )
                )
        return search_results

    def _search_code_semantic(
        self,
        query: str,
        limit: int,
        offset: int,
        similarity_threshold: float,
        include_full_code: bool,
        preview_length: int,
        total_functions: int,  # Added total_functions to correctly calculate semantic_total
    ) -> tuple[list[CodeSearchResult], int]:  # Changed return type to int for semantic_total
        if self.program_info.code_collection is None:
            raise ValueError(
                "Code indexing is not complete for this binary. "
                "Semantic search and literal search are not available yet. "
                "Wait a few seconds and retry."
            )
        search_results: list[CodeSearchResult] = []
        # Semantic search
        results = self.program_info.code_collection.query(
            query_texts=[query],
            n_results=limit + offset,
        )

        docs_list = results.get("documents") if results else None
        semantic_total = total_functions  # Initialize semantic_total here

        if results and docs_list and len(docs_list) > 0 and docs_list[0]:
            # Apply offset
            docs = docs_list[0][offset:]
            metadatas_list = results.get("metadatas")
            distances_list = results.get("distances")
            metadatas = (
                metadatas_list[0][offset:] if metadatas_list and len(metadatas_list) > 0 else []
            )
            distances = (
                distances_list[0][offset:] if distances_list and len(distances_list) > 0 else []
            )

            for i, doc in enumerate(docs):
                metadata = metadatas[i] if i < len(metadatas) else {}
                distance = distances[i] if i < len(distances) else 0
                # ChromaDB uses L2 distance by default (0 = identical, can be > 1)
                # Normalize to 0-1 range where 1 = identical
                similarity = 1 / (1 + distance)

                # Skip results below similarity threshold
                if similarity < similarity_threshold:
                    continue

                code = doc
                preview = None

                if not include_full_code:
                    preview = code[:preview_length] + "..." if len(code) > preview_length else code
                    code = preview

                search_results.append(
                    CodeSearchResult(
                        function_name=str(
                            metadata.get("function_name", "unknown")
                            if isinstance(metadata, dict)
                            else "unknown"
                        ),
                        code=code,
                        similarity=similarity,
                        search_mode=SearchMode.SEMANTIC,
                        preview=preview,
                    )
                )

            # Refine semantic_total
            # If we got fewer results than requested limit (after filtering),
            # providing we fetched enough (n_results was limit+offset)
            # and we processed strictly what we asked for.
            # Actually, if the RAW result count was less than n_results, we know we exhausted
            # the DB.
            # If valid_results_count < limit, we *might* have exhausted matches above threshold
            # in this batch.
            # A better heuristic: if result count < limit, we found everything.
            if len(search_results) < limit:
                # This is only accurate if we assume we found "the end".
                # However, since we queried limit + offset, if we got less than limit (and we
                # started at offset),
                # it implies we are at the tail.
                semantic_total = offset + len(search_results)

        return search_results, semantic_total

    @handle_exceptions
    def search_code(
        self,
        query: str,
        limit: int = 10,
        offset: int = 0,
        search_mode: SearchMode = SearchMode.SEMANTIC,
        include_full_code: bool = True,
        preview_length: int = 500,
        similarity_threshold: float = 0.0,
    ) -> CodeSearchResults:
        """
        Searches the code in the binary for a given query.

        Supports semantic (vector similarity) and literal (exact match) modes.
        Always returns dual-mode counts to help LLM decide on mode switching.

        Args:
            similarity_threshold: Minimum similarity score (0.0-1.0) for semantic results.
                                  Results below this threshold are filtered out.
        """
        if not self.program_info.code_collection:
            raise ValueError(
                "Code indexing is not complete for this binary. Please try again later."
            )

        # ALWAYS get literal count (reuse for literal mode search)
        literal_results = self.program_info.code_collection.get(where_document={"$contains": query})
        literal_total = (
            len(literal_results["ids"]) if literal_results and literal_results.get("ids") else 0
        )

        # Total functions in collection (absolute total)
        total_functions = self.program_info.code_collection.count()

        # Default semantic total to "available" (filtered by limit)
        # If we filter and get FEWER than requested, we effectively found "all" above threshold
        # in this range.
        # But we don't know beyond the limit.
        # So we default to total_functions as "estimated matches" if we hit the limit.
        semantic_total = total_functions

        search_results: list[CodeSearchResult] = []

        if search_mode == SearchMode.LITERAL:
            search_results = self._search_code_literal(
                literal_results, limit, offset, include_full_code, preview_length
            )
        else:
            search_results, estimated_total = self._search_code_semantic(
                query,
                limit,
                offset,
                similarity_threshold,
                include_full_code,
                preview_length,
                total_functions,
            )
            if estimated_total is not None:
                semantic_total = estimated_total

        return CodeSearchResults(
            results=search_results,
            query=query,
            search_mode=search_mode,
            returned_count=len(search_results),
            offset=offset,
            limit=limit,
            literal_total=literal_total,
            semantic_total=semantic_total,
            total_functions=total_functions,
        )

    @handle_exceptions
    def search_strings(self, query: str, limit: int = 100) -> list[StringSearchResult]:
        """Searches for strings within a binary using substring matching."""

        if self.program_info.strings is None:
            raise ValueError(
                "String indexing is not complete for this binary. Please try again later."
            )

        query_lower = query.lower()
        return [
            StringSearchResult(value=s.value, address=s.address, similarity=1.0)
            for s in self.program_info.strings
            if query_lower in s.value.lower()
        ][:limit]

    @handle_exceptions
    def read_bytes(self, address: str, size: int = 32) -> BytesReadResult:
        """Reads raw bytes from memory at a specified address."""
        # Maximum size limit to prevent excessive memory reads
        max_read_size = 8192

        if size <= 0:
            raise ValueError("size must be > 0")

        if size > max_read_size:
            raise ValueError(f"Size {size} exceeds maximum {max_read_size}")

        # Get address factory and parse address
        af = self.program.getAddressFactory()

        try:
            # Handle common hex address formats
            addr_str = address
            if address.lower().startswith("0x"):
                addr_str = address[2:]

            addr = af.getAddress(addr_str)
            if addr is None:
                raise ValueError(f"Invalid address: {address}")
        except Exception as e:
            raise ValueError(f"Invalid address format '{address}': {e}") from e

        # Check if address is in valid memory
        mem = self.program.getMemory()
        if not mem.contains(addr):
            raise ValueError(f"Address {address} is not in mapped memory")

        # Use JPype to handle byte arrays properly for PyGhidra
        # Create Java byte array - JPype's runtime magic confuses static type checkers
        buf = JByte[size]  # type: ignore[reportInvalidTypeArguments]
        n = mem.getBytes(addr, buf)

        # Convert Java signed bytes (-128 to 127) to Python unsigned (0 to 255)
        if n > 0:
            data = bytes([b & 0xFF for b in buf[:n]])  # type: ignore[reportGeneralTypeIssues]
        else:
            data = b""

        return BytesReadResult(
            address=str(addr),
            size=len(data),
            data=data.hex(),
        )

    @handle_exceptions
    def disassemble(
        self, address: str, count: int = 20, include_bytes: bool = False
    ) -> "DisassembleResult":
        """Disassembles instructions starting at an address.

        Returns a compact, whitespace-aligned text listing rather than per-instruction
        JSON objects to minimize token usage. Raw instruction bytes are omitted unless
        ``include_bytes`` is True.
        """
        af = self.program.getAddressFactory()
        try:
            addr_str = address[2:] if address.lower().startswith("0x") else address
            addr = af.getAddress(addr_str)
            if addr is None:
                raise ValueError(f"Invalid address: {address}")
        except Exception as e:
            raise ValueError(f"Invalid address format '{address}': {e}") from e

        if not self.program.getMemory().contains(addr):
            raise ValueError(f"Address {address} is not in mapped memory")

        listing = self.program.getListing()
        rows: list[tuple[str, str, str, str]] = []
        for insn in listing.getInstructions(addr, True):
            if len(rows) >= count:
                break
            raw = bytes([b & 0xFF for b in insn.getBytes()])
            operand_parts = []
            for i in range(insn.getNumOperands()):
                rep = insn.getDefaultOperandRepresentation(i)
                if rep:
                    operand_parts.append(str(rep))
            rows.append(
                (
                    str(insn.getAddress()),
                    raw.hex(),
                    str(insn.getMnemonicString()),
                    ",".join(operand_parts),
                )
            )

        listing_text = self._format_disassembly(rows, include_bytes=include_bytes)
        return DisassembleResult(address=str(addr), count=len(rows), listing=listing_text)

    @staticmethod
    def _format_disassembly(rows: list[tuple[str, str, str, str]], include_bytes: bool) -> str:
        """Render disassembly rows as a compact, single-space-separated text listing.

        Columns are ordered address [bytes] mnemonic operands. No alignment padding is
        used: the consumer is an LLM that parses each line positionally, and padding
        spaces only add tokens without aiding comprehension.
        """
        lines = []
        for addr, raw, mnem, operands in rows:
            parts = [addr]
            if include_bytes:
                parts.append(raw)
            parts.append(mnem)
            if operands:
                parts.append(operands)
            lines.append(" ".join(parts))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Hook-porting fidelity: call-site stack analysis + port verification
    # ------------------------------------------------------------------

    def _pointer_size(self) -> int:
        size_bits = self.program.getAddressFactory().getDefaultAddressSpace().getSize()
        return max(4, int(size_bits) // 8)

    @staticmethod
    def _operand_reprs(insn) -> list[str]:
        operands = []
        for i in range(insn.getNumOperands()):
            rep = insn.getDefaultOperandRepresentation(i)
            if rep:
                operands.append(str(rep))
        return operands

    @staticmethod
    def _note_jump_target(insn, flow, body, jump_targets: set[str]) -> None:
        if not flow.isJump():
            return
        for ref in insn.getReferencesFrom():
            to = ref.getToAddress()
            if to is not None and body.contains(to):
                jump_targets.add(str(to))

    @staticmethod
    def _resolve_call_target(insn, fm) -> tuple:
        """Resolve a direct-call target to (name, address, convention, params)."""
        for ref in insn.getReferencesFrom():
            try:
                if not ref.getReferenceType().isCall():
                    continue
            except Exception:
                continue
            callee = fm.getFunctionAt(ref.getToAddress())
            if callee is None:
                continue
            if callee.isThunk():
                thunked = callee.getThunkedFunction(False)
                if thunked is not None:
                    callee = thunked
            try:
                convention = callee.getCallingConventionName()
            except Exception:
                convention = None
            try:
                param_count = int(callee.getParameterCount())
            except Exception:
                param_count = None
            return str(callee.getName()), str(ref.getToAddress()), convention, param_count
        return None, None, None, None

    def _collect_insn_records(self, func: "Function") -> tuple[list, set[str]]:
        """Linearize a function body into analyzer-ready instruction records.

        Returns (records, jump_targets). Records are
        :class:`callsite_analysis.InsnRecord`; jump_targets holds the string
        addresses inside the body that are branch destinations.
        """
        from ghidra_nexus.callsite_analysis import InsnRecord

        listing = self.program.getListing()
        fm = self.program.getFunctionManager()
        body = func.getBody()

        records: list = []
        jump_targets: set[str] = []
        for insn in listing.getInstructions(body, True):
            flow = insn.getFlowType()
            is_call = bool(flow.isCall())
            self._note_jump_target(insn, flow, body, jump_targets)

            target_name = target_address = callee_convention = None
            callee_param_count = None
            if is_call:
                (
                    target_name,
                    target_address,
                    callee_convention,
                    callee_param_count,
                ) = self._resolve_call_target(insn, fm)

            records.append(
                InsnRecord(
                    address=str(insn.getAddress()),
                    mnemonic=str(insn.getMnemonicString()),
                    operands=self._operand_reprs(insn),
                    is_call=is_call,
                    is_ret=bool(flow.isTerminal()),
                    is_unconditional_jump=bool(flow.isJump() and flow.isUnConditional()),
                    is_indirect_call=is_call and target_address is None,
                    target_name=target_name,
                    target_address=target_address,
                    callee_convention=callee_convention,
                    callee_param_count=callee_param_count,
                )
            )
        return records, jump_targets

    @handle_exceptions
    def analyze_call_sites(
        self,
        name_or_address: str,
        max_scan: int = 40,
        binary_name: str = "",
    ) -> "CallSiteAnalysisResult":
        """Reconstruct stack-argument evidence for every CALL in a function.

        For each call site, walks backwards collecting PUSH / MOV [sp+X]
        writes, resolves one level of register indirection, and infers the
        calling convention with an explicit confidence level. Designed for
        hook porting, where decompiler pseudocode can hide a non-standard
        push order.
        """
        from ghidra_nexus.callsite_analysis import analyze_call_sites as _analyze

        func = self.find_function(name_or_address)
        records, jump_targets = self._collect_insn_records(func)
        sites = _analyze(
            records,
            pointer_size=self._pointer_size(),
            max_scan=max_scan,
            jump_targets=frozenset(jump_targets),
        )
        self._apply_pcode_fallback(func, sites)
        return CallSiteAnalysisResult(
            function_name=str(func.getName()),
            function_address=str(func.getEntryPoint()),
            binary_name=binary_name,
            call_sites=[CallSiteInfo(**s.to_dict()) for s in sites],
            total_call_sites=len(sites),
        )

    def _apply_pcode_fallback(self, func: "Function", sites: list) -> None:
        """Cross-check low-evidence indirect call sites against decompiler P-code.

        At most one decompile per call. Any failure degrades silently to
        listing-only evidence — the fallback is a cross-check, never required.
        """
        from ghidra_nexus.callsite_analysis import (
            apply_pcode_arg_count,
            needs_pcode_fallback,
        )

        flagged = [s for s in sites if needs_pcode_fallback(s)]
        if not flagged:
            return
        try:
            from ghidra.program.model.pcode import PcodeOp
            from ghidra.util.task import ConsoleTaskMonitor
        except Exception:
            logger.debug("p-code fallback unavailable", exc_info=True)
            return
        try:
            with self.decompiler_pool.acquire() as decompiler:
                results = decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())
                if results is None or not results.decompileCompleted():
                    logger.debug(
                        "p-code fallback: decompile incomplete for %s", func.getName()
                    )
                    return
                high = results.getHighFunction()
                if high is None:
                    return
                for site in flagged:
                    addr = self._parse_address(site.address)
                    count = self._pcode_call_arg_count(high, addr, PcodeOp)
                    if count is not None:
                        apply_pcode_arg_count(site, count)
        except Exception:
            logger.debug("p-code fallback failed for %s", func.getName(), exc_info=True)

    @staticmethod
    def _pcode_call_arg_count(high, addr, pcode_op_cls) -> int | None:
        """Argument count of the CALL/CALLIND P-code op at ``addr`` (inputs - 1)."""
        ops = high.getPcodeOps(addr)
        while ops.hasNext():
            op = ops.next()
            if op.getOpcode() in (pcode_op_cls.CALL, pcode_op_cls.CALLIND):
                return max(0, int(op.getNumInputs()) - 1)
        return None

    def _register_clobbers(self, func: "Function") -> dict:
        """Conservative register-write scan for hook planning.

        Collects every register written in the body (via result objects),
        then classifies them into saved (pushed in the prologue and popped
        before returning) vs clobbered, split by ABI volatility.
        """
        from ghidra.program.model.lang import Register

        from ghidra_nexus.callsite_analysis import classify_registers

        listing = self.program.getListing()
        written: set[str] = set()
        pushed_prologue: set[str] = set()
        popped: set[str] = set()
        seen_call = False
        for insn in listing.getInstructions(func.getBody(), True):
            flow = insn.getFlowType()
            for obj in insn.getResultObjects():
                if isinstance(obj, Register):
                    written.add(str(obj.getBaseRegister().getName()).lower())
            mnem = str(insn.getMnemonicString()).lower()
            if mnem not in ("push", "pop") or insn.getNumOperands() == 0:
                if flow.isCall():
                    seen_call = True
                continue
            rep = insn.getDefaultOperandRepresentation(0)
            if not rep:
                continue
            reg = str(rep).lower()
            if mnem == "push":
                if not seen_call:
                    pushed_prologue.add(reg)
            else:
                popped.add(reg)
            if flow.isCall():
                seen_call = True
        return classify_registers(
            written, pushed_prologue & popped, self._pointer_size()
        )

    @staticmethod
    def _norm_conv(conv: str | None) -> str:
        return (conv or "").lower().lstrip("_").replace(" ", "")

    @staticmethod
    def _reg_arg_count(calling_convention: str) -> int:
        """Register-passed argument count implied by a convention (x86-32)."""
        conv = (calling_convention or "").lower()
        if "thiscall" in conv:
            return 1  # ecx
        if "fastcall" in conv:
            return 2  # ecx, edx
        return 0

    def _expected_stack_param_bytes(
        self, calling_convention: str, arg_lengths: list[int], ptr: int
    ) -> int:
        """Bytes of stack-passed parameters implied by a convention."""
        reg_args = self._reg_arg_count(calling_convention)
        stack_lengths = arg_lengths[reg_args:] if len(arg_lengths) > reg_args else []
        slots = [((length + ptr - 1) // ptr) * ptr for length in stack_lengths]
        return sum(slots)

    @staticmethod
    def _add_check(
        checks: list[VerifyPortCheck],
        name: str,
        expected: object,
        actual: object,
        status: str,
    ) -> None:
        checks.append(
            VerifyPortCheck(
                name=name,
                expected=str(expected),
                actual=str(actual),
                status=status,
            )
        )

    def _parse_proposed_signature(
        self, func: "Function", signature: str, ptr: int
    ) -> tuple[str, list[int]]:
        """Parse a proposed C prototype. Returns (convention, arg lengths)."""
        from ghidra.app.util.parser import FunctionSignatureParser

        parser = FunctionSignatureParser(
            self.program.getDataTypeManager(), typing.cast(typing.Any, None)
        )
        try:
            parsed = parser.parse(func.getSignature(False), signature)
        except Exception as e:
            raise ValueError(f"Could not parse signature '{signature}': {e}") from e
        if parsed is None:
            raise ValueError(f"Could not parse signature '{signature}'")

        conv = str(parsed.getCallingConventionName() or "")
        lengths: list[int] = []
        for arg in parsed.getArguments():
            try:
                lengths.append(max(1, int(arg.getDataType().getLength())))
            except Exception:
                lengths.append(ptr)
        return conv, lengths

    @handle_exceptions
    def verify_port(
        self,
        name_or_address: str,
        signature: str,
        call_site: str | None = None,
        binary_name: str = "",
    ) -> "VerifyPortResult":
        """Pre-flight check of a proposed ported signature against binary evidence.

        Compares calling convention, parameter count, and stack-parameter
        byte count (from ``ret N`` epilogues or call-site push evidence)
        between the proposed C-style signature and what the binary actually
        does. Read-only: parses the signature but never applies it.
        """
        func = self.find_function(name_or_address)
        ptr = self._pointer_size()
        proposed_conv, proposed_arg_lengths = self._parse_proposed_signature(
            func, signature, ptr
        )
        clobbers = self._register_clobbers(func)
        if call_site is not None:
            return self._verify_port_at_call_site(
                func,
                name_or_address,
                signature,
                call_site,
                proposed_conv,
                len(proposed_arg_lengths),
                binary_name,
                clobbers,
            )
        return self._verify_port_at_function(
            func,
            name_or_address,
            signature,
            proposed_conv,
            proposed_arg_lengths,
            ptr,
            binary_name,
            clobbers,
        )

    def _make_verify_result(
        self,
        target: str,
        signature: str,
        binary_name: str,
        addr: str,
        checks: list[VerifyPortCheck],
        warnings: list[str],
        clobbers: dict | None = None,
    ) -> "VerifyPortResult":
        clobbers = clobbers or {}
        saved = clobbers.get("saved", [])
        c_vol = clobbers.get("clobbered_volatile", [])
        c_nv = clobbers.get("clobbered_non_volatile", [])
        if clobbers:
            self._add_check(
                checks,
                "register_preservation",
                f"non-volatile clobbers: {', '.join(c_nv) or 'none'}",
                "hook must save/restore any non-volatile clobbers",
                "warn" if c_nv else "pass",
            )
        else:
            warnings = [
                *warnings,
                "Register-clobber analysis unavailable for this target; "
                "save/restore registers conservatively in the hook stub.",
            ]
        verdict = "fail" if any(c.status == "fail" for c in checks) else "pass"
        hint = (
            "Fix the failing checks and re-run verify_port; "
            "disassemble_call_site shows the raw stack evidence."
            if verdict == "fail"
            else None
        )
        return VerifyPortResult(
            target=target,
            proposed_signature=signature,
            binary_name=binary_name,
            addr=addr,
            checks=checks,
            verdict=verdict,
            warnings=warnings,
            hint=hint,
            saved_registers=saved,
            clobbered_volatile=c_vol,
            clobbered_non_volatile=c_nv,
        )

    def _verify_port_at_call_site(
        self,
        func: "Function",
        target: str,
        signature: str,
        call_site: str,
        proposed_conv: str,
        proposed_arg_count: int,
        binary_name: str,
        clobbers: dict | None = None,
    ) -> "VerifyPortResult":
        site_addr = str(self._parse_address(call_site))
        sites = self.analyze_call_sites(
            str(func.getEntryPoint()), binary_name=binary_name
        ).call_sites
        site = next((s for s in sites if s.address == site_addr), None)
        if site is None:
            raise ValueError(
                f"No call instruction found at {site_addr} in function "
                f"'{func.getName()}'."
            )

        checks: list[VerifyPortCheck] = []
        expected_stack_args = max(
            0, proposed_arg_count - self._reg_arg_count(proposed_conv)
        )
        self._add_check(
            checks,
            "stack_param_count",
            f"{len(site.stack_args)} observed at call site",
            f"{expected_stack_args} stack-passed in proposed signature",
            "pass" if len(site.stack_args) == expected_stack_args else "fail",
        )
        if "thiscall" in self._norm_conv(proposed_conv):
            self._add_check(
                checks,
                "this_pointer",
                "ECX written before call (thiscall requires this in ECX)",
                site.ecx_source or "no ECX write observed",
                "pass" if site.ecx_source is not None else "fail",
            )
        if site.inferred_convention and "?" not in site.inferred_convention:
            match = self._norm_conv(site.inferred_convention) == self._norm_conv(
                proposed_conv
            )
            self._add_check(
                checks,
                "calling_convention",
                site.inferred_convention,
                proposed_conv or "unspecified",
                "pass" if match else "fail",
            )
        return self._make_verify_result(
            target, signature, binary_name, site_addr, checks, list(site.warnings),
            clobbers,
        )

    def _verify_port_at_function(
        self,
        func: "Function",
        target: str,
        signature: str,
        proposed_conv: str,
        proposed_arg_lengths: list[int],
        ptr: int,
        binary_name: str,
        clobbers: dict | None = None,
    ) -> "VerifyPortResult":
        checks: list[VerifyPortCheck] = []
        warnings: list[str] = []
        self._check_declared_convention(func, proposed_conv, checks, warnings)
        self._check_declared_param_count(func, len(proposed_arg_lengths), checks)
        self._check_ret_cleanup(
            func, proposed_conv, proposed_arg_lengths, ptr, checks, warnings
        )
        return self._make_verify_result(
            target, signature, binary_name, str(func.getEntryPoint()), checks,
            warnings, clobbers,
        )

    def _check_declared_convention(
        self,
        func: "Function",
        proposed_conv: str,
        checks: list[VerifyPortCheck],
        warnings: list[str],
    ) -> None:
        actual_conv = None
        try:
            actual_conv = func.getCallingConventionName()
        except Exception:
            actual_conv = None
        if actual_conv and self._norm_conv(actual_conv) not in ("default", "unknown", ""):
            match = self._norm_conv(actual_conv) == self._norm_conv(proposed_conv)
            self._add_check(
                checks,
                "calling_convention",
                actual_conv,
                proposed_conv or "unspecified",
                "pass" if match else "fail",
            )
            return
        self._add_check(
            checks,
            "calling_convention",
            "no convention declared in Ghidra",
            proposed_conv or "unspecified",
            "warn",
        )
        warnings.append(
            "Binary has no declared calling convention for this function; "
            "verify the convention by hand (disassemble_call_site)."
        )

    def _check_declared_param_count(
        self,
        func: "Function",
        proposed_arg_count: int,
        checks: list[VerifyPortCheck],
    ) -> None:
        try:
            actual_param_count = int(func.getParameterCount())
        except Exception:
            return
        self._add_check(
            checks,
            "param_count",
            f"{actual_param_count} declared in Ghidra",
            f"{proposed_arg_count} in proposed signature",
            "pass" if actual_param_count == proposed_arg_count else "warn",
        )

    def _check_ret_cleanup(
        self,
        func: "Function",
        proposed_conv: str,
        proposed_arg_lengths: list[int],
        ptr: int,
        checks: list[VerifyPortCheck],
        warnings: list[str],
    ) -> None:
        """Independent evidence: RET N epilogues (callee-cleaned stack bytes)."""
        cleaned = self._ret_cleanup_bytes(func)
        proposed_stack_bytes = self._expected_stack_param_bytes(
            proposed_conv, proposed_arg_lengths, ptr
        )
        if cleaned is not None:
            self._add_check(
                checks,
                "stack_param_bytes",
                f"ret {cleaned} epilogue (callee cleans {cleaned} bytes)",
                f"{proposed_stack_bytes} stack bytes implied by proposed signature",
                "pass" if cleaned == proposed_stack_bytes else "fail",
            )
            return
        self._add_check(
            checks,
            "stack_param_bytes",
            "no ret N epilogue found (caller-cleanup or unknown)",
            f"{proposed_stack_bytes} stack bytes implied by proposed signature",
            "warn",
        )
        if "cdecl" not in self._norm_conv(proposed_conv) and proposed_stack_bytes > 0:
            warnings.append(
                "No ret N epilogue found, but the proposed convention is "
                "callee-cleanup; double-check the epilogue manually."
            )

    def _ret_cleanup_bytes(self, func: "Function") -> int | None:
        """Return N if every ``ret N`` in the body cleans the same N, else None.

        A bare ``ret`` (no operand) cleans 0 bytes; a function with only bare
        rets returns 0. Mixed or absent values return None (inconclusive).
        """
        listing = self.program.getListing()
        values: set[int] = set()
        saw_ret = False
        for insn in listing.getInstructions(func.getBody(), True):
            if not insn.getFlowType().isTerminal():
                continue
            mnemonic = str(insn.getMnemonicString()).lower()
            if not mnemonic.startswith("ret"):
                continue
            saw_ret = True
            if insn.getNumOperands() == 0:
                values.add(0)
                continue
            rep = insn.getDefaultOperandRepresentation(0)
            try:
                values.add(int(str(rep), 0) if rep else 0)
            except (TypeError, ValueError):
                try:
                    values.add(int(str(rep).rstrip("h"), 16))
                except (TypeError, ValueError):
                    return None
        if not saw_ret or len(values) != 1:
            return None
        return values.pop()

    @handle_exceptions
    def gen_callgraph(
        self,
        function_name_or_address: str,
        cg_direction: CallGraphDirection = CallGraphDirection.CALLING,
        cg_display_type: CallGraphDisplayType = CallGraphDisplayType.FLOW,
        include_refs: bool = True,
        max_depth: int | None = None,
        max_run_time: int = 60,
        condense_threshold: int = 50,
        top_layers: int = 5,
        bottom_layers: int = 5,
    ) -> CallGraphResult:
        """Generates a call graph for a specified function."""

        cg_func = self.find_function(function_name_or_address)
        mermaid_url: str = ""

        # Call the ghidrecomp function
        name, direction, _, graphs_data = gen_callgraph(
            func=cg_func,
            max_display_depth=max_depth,
            direction=cg_direction.value,
            max_run_time=max_run_time,
            name=cg_func.getSymbol().getName(True),
            include_refs=include_refs,
            condense_threshold=condense_threshold,
            top_layers=top_layers,
            bottom_layers=bottom_layers,
            wrap_mermaid=False,
        )

        selected_graph_content = ""
        for graph_type, graph_content in graphs_data:
            if CallGraphDisplayType(graph_type) == cg_display_type:
                selected_graph_content = graph_content
                break

        if not selected_graph_content:
            raise ValueError(
                f"Cg display type {cg_display_type.value} not found for function {cg_func}."
            )

        for graph_type, graph_content in graphs_data:
            if graph_type == "mermaid_url":
                mermaid_url = graph_content.split("\n")[0]
                break

        return CallGraphResult(
            function_name=name,
            direction=CallGraphDirection(direction),
            display_type=cg_display_type,
            graph=selected_graph_content,
            mermaid_url=mermaid_url,
        )

    @handle_exceptions
    def rename_function(self, name_or_address: str, new_name: str) -> dict:
        from ghidra.program.model.symbol import SourceType

        func = self.find_function(name_or_address)
        old_name = str(func.getName())
        address = str(func.getEntryPoint())

        with ghidra_transaction(
            self.program,
            f"nexus: rename {old_name} -> {new_name}",
        ):
            func.setName(new_name, SourceType.USER_DEFINED)

        self.invalidate_decompiler_cache()
        return {
            "address": address,
            "old_name": old_name,
            "new_name": new_name,
        }

    @handle_exceptions
    def rename_variable(
        self,
        function_name_or_address: str,
        variable_name: str,
        new_name: str,
    ) -> dict:
        from ghidra.program.model.symbol import SourceType

        func, variable_kind, variable = self._resolve_function_variable(
            function_name_or_address, variable_name
        )
        old_name = str(variable_name)
        function_name = str(func.getName())
        function_address = str(func.getEntryPoint())
        with ghidra_transaction(
            self.program,
            f"nexus: rename {variable_kind} {old_name} -> {new_name}",
        ):
            variable.setName(new_name, SourceType.USER_DEFINED)

        self.invalidate_decompiler_cache()
        return {
            "function_name": function_name,
            "function_address": function_address,
            "variable_kind": variable_kind,
            "old_name": old_name,
            "new_name": new_name,
        }

    @handle_exceptions
    def set_variable_type(
        self,
        function_name_or_address: str,
        variable_name: str,
        type_name: str,
    ) -> dict:
        from ghidra.program.model.symbol import SourceType

        func, variable_kind, variable = self._resolve_function_variable(
            function_name_or_address, variable_name
        )
        function_name = str(func.getName())
        function_address = str(func.getEntryPoint())
        old_type = str(variable.getDataType().getDisplayName())
        data_type = self._parse_data_type(type_name)

        with ghidra_transaction(
            self.program,
            f"nexus: set {variable_kind} type {variable_name} -> {type_name}",
        ):
            variable.setDataType(data_type, SourceType.USER_DEFINED)

        self.invalidate_decompiler_cache()
        return {
            "function_name": function_name,
            "function_address": function_address,
            "variable_kind": variable_kind,
            "variable_name": str(variable.getName()),
            "old_type": old_type,
            "new_type": str(variable.getDataType().getDisplayName()),
        }

    @handle_exceptions
    def set_function_prototype(
        self,
        function_name_or_address: str,
        prototype: str,
    ) -> dict:
        from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
        from ghidra.app.util.parser import FunctionSignatureParser
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import TaskMonitor

        func = self.find_function(function_name_or_address)
        function_name = str(func.getName())
        function_address = str(func.getEntryPoint())
        old_prototype = str(func.getSignature())

        parser = FunctionSignatureParser(
            self.program.getDataTypeManager(), typing.cast(typing.Any, None)
        )
        parsed_signature = parser.parse(func.getSignature(False), prototype)
        cmd = ApplyFunctionSignatureCmd(
            func.getEntryPoint(),
            parsed_signature,
            SourceType.USER_DEFINED,
        )

        with ghidra_transaction(
            self.program,
            f"nexus: set function prototype {function_name}",
        ):
            if not cmd.applyTo(self.program, TaskMonitor.DUMMY):
                message = cmd.getStatusMsg() or f"Failed to apply function prototype: {prototype}"
                raise ValueError(message)

        self.invalidate_decompiler_cache()
        return {
            "function_name": function_name,
            "function_address": function_address,
            "old_prototype": old_prototype,
            "new_prototype": str(func.getSignature()),
        }

    @handle_exceptions
    def set_comment(self, target: str, comment: str, comment_type: str) -> dict:
        try:
            from ghidra.program.model.listing import CommentType

            listing_comment_types = {
                "plate": CommentType.PLATE,
                "pre": CommentType.PRE,
                "eol": CommentType.EOL,
                "post": CommentType.POST,
                "repeatable": CommentType.REPEATABLE,
            }
        except ImportError:
            from ghidra.program.model.listing import CodeUnit

            listing_comment_types = {
                "plate": CodeUnit.PLATE_COMMENT,
                "pre": CodeUnit.PRE_COMMENT,
                "eol": CodeUnit.EOL_COMMENT,
                "post": CodeUnit.POST_COMMENT,
                "repeatable": CodeUnit.REPEATABLE_COMMENT,
            }

        normalized_type = comment_type.lower()
        if normalized_type == "decompiler":
            func = self.find_function(target)
            addr = func.getEntryPoint()

            with ghidra_transaction(
                self.program,
                f"nexus: set function comment @ {addr}",
            ):
                func.setComment(comment)

            self.invalidate_decompiler_cache()
            return {
                "address": str(addr),
                "comment": comment,
                "comment_type": "decompiler",
            }

        ghidra_comment_type = listing_comment_types.get(normalized_type)
        if ghidra_comment_type is None:
            allowed = ["decompiler", *listing_comment_types.keys()]
            raise ValueError(f"Invalid comment_type '{comment_type}'. Expected one of: {allowed}")

        addr = self._resolve_comment_target_address(target)
        with ghidra_transaction(
            self.program,
            f"nexus: set {normalized_type} comment @ {addr}",
        ):
            self.program.getListing().setComment(addr, ghidra_comment_type, comment)

        self.invalidate_decompiler_cache()
        return {
            "address": str(addr),
            "comment": comment,
            "comment_type": normalized_type,
        }

    def invalidate_decompiler_cache(self) -> None:
        try:
            self.decompiler_pool.invalidate_all()
        except Exception:
            logger.debug("Failed to invalidate decompiler cache", exc_info=True)

    def _parse_address(self, address: str):
        addr_str = address[2:] if address.lower().startswith("0x") else address
        addr = self.program.getAddressFactory().getAddress(addr_str)
        if addr is None:
            raise ValueError(f"Invalid address: {address}")
        return addr

    def _resolve_comment_target_address(self, target: str):
        try:
            return self._parse_address(target)
        except Exception:
            pass

        if target.isdigit():
            addr = self.program.getAddressFactory().getDefaultAddressSpace().getAddress(int(target))
            if addr is not None:
                return addr

        try:
            return self.find_symbol(target).getAddress()
        except Exception:
            pass

        try:
            return self.find_function(target).getEntryPoint()
        except Exception:
            pass

        raise ValueError(
            f"Could not resolve comment target '{target}' as an address, symbol, or function."
        )
