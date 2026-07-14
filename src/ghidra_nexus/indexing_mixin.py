import concurrent.futures
import logging
import threading
from pathlib import Path
from typing import Any

import chromadb
from chromadb.config import Settings

from ghidra_nexus.tools import GhidraTools

logger = logging.getLogger(__name__)

# Collection metadata key flipped to True only after a code index is fully
# populated. A collection missing this marker (legacy) or carrying False (an
# interrupted/partial index) is rebuilt rather than trusted on restart.
COLLECTION_COMPLETE_KEY = "nexus_index_complete"


class IndexingMixin:
    """Shared MCP-side indexing behavior for headless and GUI contexts."""

    programs: dict[str, Any]

    def _init_indexing_state(self, nexus_data_dir: Path, *, threaded: bool) -> None:
        """Initialize ChromaDB ONLY when NEXUS_SEMANTIC_BACKEND=chromadb.

        Phase 3 demotion: by default, ChromaDB is NOT started. The notebook's
        sqlite-vec path serves all semantic queries. Set the env var to restore
        the legacy ChromaDB backend.
        """
        import os as _os

        use_chromadb = _os.environ.get("NEXUS_SEMANTIC_BACKEND") == "chromadb"
        chromadb_path = nexus_data_dir / "chromadb"
        if use_chromadb:
            chromadb_path.mkdir(parents=True, exist_ok=True)
            try:
                self.chroma_client = chromadb.PersistentClient(
                    path=str(chromadb_path), settings=Settings(anonymized_telemetry=False)
                )
            except Exception as e:
                logger.critical(
                    "Failed to initialize ChromaDB at %s: %s. "
                    "Creating a fresh ChromaDB directory.",
                    chromadb_path, e,
                )
                import shutil
                shutil.rmtree(str(chromadb_path), ignore_errors=True)
                chromadb_path.mkdir(parents=True, exist_ok=True)
                self.chroma_client = chromadb.PersistentClient(
                    path=str(chromadb_path), settings=Settings(anonymized_telemetry=False)
                )
                logger.info("ChromaDB re-initialized at %s", chromadb_path)
            self.chroma_client.heartbeat()
        else:
            self.chroma_client = None
            logger.info("ChromaDB disabled (default); sqlite-vec is the semantic backend")
        self.index_executor = (
            concurrent.futures.ThreadPoolExecutor(max_workers=1) if threaded else None
        )
        self._index_futures: dict[str, concurrent.futures.Future] = {}
        self._index_lock = threading.Lock()

    def shutdown_indexing(self) -> None:
        if self.index_executor:
            self.index_executor.shutdown(wait=True)

    def _lookup_program_info(self, binary_name: str) -> Any | None:
        raise NotImplementedError

    def schedule_indexing(
        self,
        binary_name: str,
        *,
        code: bool = True,
        strings: bool = True,
    ) -> bool:
        """Schedule MCP-side indexing for a binary when it is relevant."""
        program_info = self._lookup_program_info(binary_name)
        if program_info is None or not program_info.analysis_complete:
            return False
        if (not code or program_info.code_collection is not None) and (
            not strings or program_info.strings is not None
        ):
            return False

        with self._index_lock:
            future = self._index_futures.get(binary_name)
            if future is not None and not future.done():
                return False

            if self.index_executor is not None:
                future = self.index_executor.submit(
                    self._index_program,
                    program_info,
                    code=code,
                    strings=strings,
                )
                self._index_futures[binary_name] = future
                future.add_done_callback(
                    lambda done_future, name=binary_name: self._index_done_callback(
                        name, done_future
                    )
                )
                return True

        self._index_program(program_info, code=code, strings=strings)
        return True

    def schedule_startup_indexing(self, *, max_binaries: int | None = 10) -> None:
        """Eagerly index only manageable existing projects on startup."""
        analyzed_programs = [
            program_info
            for program_info in self.programs.values()
            if program_info.analysis_complete
        ]
        if max_binaries is not None and len(analyzed_programs) > max_binaries:
            logger.info(
                "Skipping startup indexing for %s binaries; indexing will start lazily.",
                len(analyzed_programs),
            )
            return

        for program_info in analyzed_programs:
            self.schedule_indexing(program_info.name)

    def _open_complete_collection(self, name: str) -> Any | None:
        """Return an existing, fully-indexed collection, or None.

        Completion is decided by the ``COLLECTION_COMPLETE_KEY`` marker, not by
        mere existence: chromadb persists a collection the moment it is created,
        so an index interrupted partway through leaves an empty/partial
        collection on disk. Such a collection (and any legacy one lacking the
        marker) is deleted here so the caller rebuilds it from scratch.
        """
        try:
            collection = self.chroma_client.get_collection(name=name)
        except Exception:
            return None

        metadata = collection.metadata or {}
        if metadata.get(COLLECTION_COMPLETE_KEY):
            return collection

        logger.warning(
            "Collection '%s' is incomplete (interrupted index?); deleting to rebuild.", name
        )
        self.chroma_client.delete_collection(name=name)
        return None

    def _mark_collection_complete(self, collection: Any, function_count: int) -> None:
        """Flip a fully-populated collection's completion marker on disk."""
        collection.modify(
            metadata={COLLECTION_COMPLETE_KEY: True, "function_count": function_count}
        )

    def _init_chroma_code_collection_for_program(self, program_info: Any) -> None:
        from ghidra.program.model.listing import Function

        logger.info("Initializing Chroma code collection for %s", program_info.name)
        existing = self._open_complete_collection(program_info.name)
        if existing is not None:
            logger.info(
                "Collection '%s' already complete; skipping code ingest.", program_info.name
            )
            program_info.code_collection = existing
            return

        logger.info("Creating new code collection '%s'", program_info.name)
        tools = GhidraTools(program_info)
        functions = tools.get_all_functions()
        decompiles = []
        ids = []
        metadatas = []
        failed_count = 0

        for i, func in enumerate(functions):
            func: Function
            try:
                if i % 10 == 0:
                    logger.debug("Decompiling %s/%s", i, len(functions))
                decompiled = tools.decompile_function(func)
                decompiles.append(decompiled.code)
                ids.append(decompiled.name)
                metadatas.append(
                    {
                        "function_name": decompiled.name,
                        "entry_point": str(func.getEntryPoint()),
                    }
                )
            except Exception as e:
                failed_count += 1
                logger.error("Failed to decompile %s: %s", func.getSymbol().getName(True), e)

        total_functions = len(functions)
        failure_pct = (failed_count / total_functions * 100) if total_functions > 0 else 0
        MAX_FAILURE_PCT = 1.0

        if failure_pct > MAX_FAILURE_PCT:
            logger.error(
                "Code index for '%s': %d/%d functions failed to decompile (%.1f%%). "
                "Collection will NOT be marked complete and will be rebuilt on next startup.",
                program_info.name, failed_count, total_functions, failure_pct,
            )
            logger.warning(
                "Code index for '%s' is incomplete: %d of %d functions could not be "
                "decompiled. Semantic search results may be incomplete. "
                "Check Ghidra health or re-open the binary with fresh analysis.",
                program_info.name, failed_count, total_functions,
            )
            return

        # Created with the completion marker off; an interruption before the
        # marker is flipped below leaves a collection that reads as incomplete
        # and is rebuilt on the next run. The add failure is intentionally not
        # swallowed: a partial index must fail loudly so it is not marked done.
        collection = self.chroma_client.create_collection(
            name=program_info.name, metadata={COLLECTION_COMPLETE_KEY: False}
        )
        batch_size = 5000
        for i in range(0, len(decompiles), batch_size):
            end = min(i + batch_size, len(decompiles))
            collection.add(
                documents=decompiles[i:end],
                metadatas=metadatas[i:end],
                ids=ids[i:end],
            )

        self._mark_collection_complete(collection, len(ids))
        logger.info("Code analysis complete for collection '%s'", program_info.name)
        program_info.code_collection = collection

    def _init_strings_for_program(self, program_info: Any) -> None:
        logger.info("Loading strings for %s", program_info.name)
        strings, dropped = GhidraTools(program_info).get_all_strings()
        if dropped > 0:
            logger.warning(
                "%d string values could not be read for '%s' (corrupted data). "
                "The string listing is incomplete.",
                dropped, program_info.name,
            )
        program_info.strings = strings
        logger.info("Loaded %s strings for %s", len(program_info.strings), program_info.name)

    def _index_program(
        self,
        program_info: Any,
        *,
        code: bool = True,
        strings: bool = True,
    ) -> None:
        if code and program_info.code_collection is None:
            self._init_chroma_code_collection_for_program(program_info)
        if strings and program_info.strings is None:
            self._init_strings_for_program(program_info)

    def _index_done_callback(
        self,
        binary_name: str,
        future: concurrent.futures.Future,
    ) -> None:
        with self._index_lock:
            self._index_futures.pop(binary_name, None)
        try:
            future.result()
            logger.info("Background indexing completed successfully for %s.", binary_name)
        except Exception:
            logger.error("Background indexing failed for %s.", binary_name, exc_info=True)
