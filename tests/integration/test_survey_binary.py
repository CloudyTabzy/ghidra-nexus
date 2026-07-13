"""Integration tests for survey_binary — runs against a real Ghidra binary.

Spins up a full pyghidra-mcp server over stdio, imports a small test binary,
waits for Ghidra analysis, then calls survey_binary and asserts the structure
mirrors the Synapse MCP contract.
"""

import json
import time

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError

from ghidra_nexus.context import PyGhidraContext
from ghidra_nexus.models import SurveyBinaryResult


def _wait_for_binary_ready(
    session: ClientSession, binary_name: str, timeout_s: int = 240
) -> dict:
    """Poll list_project_binaries until the binary is ready, then return it."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        response = await_session_call_tool(session, "list_project_binaries", {})
        text = response.content[0].text
        programs = json.loads(text)["programs"]
        for program in programs:
            if binary_name in program["name"] and program.get("analysis_complete"):
                return program
        time.sleep(1)
    raise TimeoutError(f"Binary {binary_name} did not become ready within {timeout_s}s")


async def await_session_call_tool(session: ClientSession, name: str, arguments: dict):
    """Tiny async helper so the fixture code reads top-to-bottom."""
    return await session.call_tool(name, arguments)


@pytest.mark.asyncio
async def test_survey_binary_returns_all_required_sections(server_params):
    """Standard-detail survey returns metadata, statistics, segments, entrypoints,
    and the full payload (interesting_strings, interesting_functions,
    imports_by_category, call_graph_summary)."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_path = server_params.args[-1]
            binary_name = PyGhidraContext._gen_unique_bin_name(binary_path)
            _wait_for_binary_ready(session, binary_name)

            response = await session.call_tool(
                "survey_binary", {"binary_name": binary_name, "detail_level": "standard"}
            )
            result = SurveyBinaryResult.model_validate_json(response.content[0].text)

            # Core shape — every standard field present.
            assert result.ok is True
            assert result.metadata.path
            assert result.metadata.arch in ("32", "64")
            assert result.metadata.base_address.startswith("0x")
            assert result.metadata.image_size.startswith("0x")
            assert len(result.metadata.md5) == 32
            assert len(result.metadata.sha256) == 64
            assert result.statistics.total_segments >= 1
            assert result.statistics.total_functions >= 1
            assert isinstance(result.segments, list)
            assert all(s.permissions for s in result.segments)
            assert isinstance(result.entrypoints, list)

            # The full payload sections should be populated.
            assert result.interesting_strings is not None
            assert result.interesting_functions is not None
            assert result.imports_by_category is not None
            assert result.call_graph_summary is not None


@pytest.mark.asyncio
async def test_survey_binary_minimal_omits_heavy_sections(server_params):
    """detail_level='minimal' must skip the heavy analysis sections."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_path = server_params.args[-1]
            binary_name = PyGhidraContext._gen_unique_bin_name(binary_path)
            _wait_for_binary_ready(session, binary_name)

            response = await session.call_tool(
                "survey_binary", {"binary_name": binary_name, "detail_level": "minimal"}
            )
            result = SurveyBinaryResult.model_validate_json(response.content[0].text)

            assert result.ok is True
            # Minimal mode: only metadata / statistics / segments / entrypoints.
            assert result.interesting_strings is None
            assert result.interesting_functions is None
            assert result.imports_by_category is None
            assert result.call_graph_summary is None
            # Core shape still present.
            assert result.metadata.path
            assert result.statistics.total_functions >= 1


@pytest.mark.asyncio
async def test_survey_binary_finds_main_and_strings(server_params):
    """Standard survey should surface the test binary's known symbols/strings."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_path = server_params.args[-1]
            binary_name = PyGhidraContext._gen_unique_bin_name(binary_path)
            _wait_for_binary_ready(session, binary_name)

            response = await session.call_tool(
                "survey_binary", {"binary_name": binary_name, "detail_level": "standard"}
            )
            result = SurveyBinaryResult.model_validate_json(response.content[0].text)

            # The test binary prints "Function One" and "Hello, World!"
            interesting = result.interesting_strings or []
            strings_blob = " ".join(s.string for s in interesting)
            assert any(
                needle in strings_blob
                for needle in ("Function One", "Function Two", "Hello, World!")
            ), f"Expected test-binary strings in interesting_strings, got: {strings_blob!r}"

            # The test binary has named functions like main, function_one, function_two
            interesting_funcs = result.interesting_functions or []
            names_blob = " ".join(f.name for f in interesting_funcs)
            assert any(
                n in names_blob for n in ("main", "function_one", "function_two")
            ), f"Expected test-binary functions in interesting_functions, got: {names_blob!r}"


@pytest.mark.asyncio
async def test_survey_binary_imports_grouped_by_category(server_params):
    """Test binary's libc imports should land in the right import category buckets."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_path = server_params.args[-1]
            binary_name = PyGhidraContext._gen_unique_bin_name(binary_path)
            _wait_for_binary_ready(session, binary_name)

            response = await session.call_tool(
                "survey_binary", {"binary_name": binary_name, "detail_level": "standard"}
            )
            result = SurveyBinaryResult.model_validate_json(response.content[0].text)

            cats = result.imports_by_category
            assert cats is not None
            # The test binary calls printf + free which fall under "other" since
            # they don't match the regex buckets; at minimum the "other" bucket
            # should not be empty.
            all_imports = (
                cats.crypto
                + cats.network
                + cats.file_io
                + cats.process
                + cats.registry
                + cats.other
            )
            assert len(all_imports) > 0


@pytest.mark.asyncio
async def test_survey_binary_refuses_unknown_binary(server_params):
    """Calling survey_binary on a non-existent binary name should error, not crash."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Server is up but the binary is not imported.
            with pytest.raises((McpError, ValueError, RuntimeError)):
                await session.call_tool(
                    "survey_binary",
                    {"binary_name": "definitely_not_a_real_binary_xyz", "detail_level": "standard"},
                )


@pytest.mark.asyncio
async def test_survey_binary_fast_returns_immediately_pre_analysis(server_params):
    """survey_binary_fast should work BEFORE Ghidra analysis completes.

    This is the headline benefit of the fast variant: agents get a
    useful triage in milliseconds without waiting for the 5-10 minute
    Ghidra analysis. We import the binary, call survey_binary_fast
    immediately (before the analysis-complete poll), and verify we got
    a real payload with mode='fast'.
    """
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_path = server_params.args[-1]
            binary_name = PyGhidraContext._gen_unique_bin_name(binary_path)

            # Import only — do NOT wait for analysis.
            response = await session.call_tool(
                "import_binary", {"binary_path": binary_path}
            )
            imp = json.loads(response.content[0].text)
            assert imp["queued_count"] == 1

            # survey_binary_fast should return immediately, regardless of
            # whether the import has even appeared in project listing yet.
            response = await session.call_tool(
                "survey_binary_fast", {"binary_name": binary_name}
            )
            result = SurveyBinaryResult.model_validate_json(response.content[0].text)

            # mode must be 'fast' and the result must carry a pre-analysis
            # note so the agent can tell what it's looking at.
            assert result.mode == "fast"
            assert result.note is not None
            assert "pre-analysis" in result.note.lower()


@pytest.mark.asyncio
async def test_survey_binary_full_alias_matches_survey_binary(server_params):
    """The legacy survey_binary tool and survey_binary_full return the same shape."""
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            binary_path = server_params.args[-1]
            binary_name = PyGhidraContext._gen_unique_bin_name(binary_path)
            _wait_for_binary_ready(session, binary_name)

            # Call BOTH the legacy alias and the new full variant; results
            # must agree on the structural fields we care about.
            legacy = SurveyBinaryResult.model_validate_json(
                (
                    await session.call_tool(
                        "survey_binary",
                        {"binary_name": binary_name, "detail_level": "standard"},
                    )
                ).content[0].text
            )
            full = SurveyBinaryResult.model_validate_json(
                (
                    await session.call_tool(
                        "survey_binary_full",
                        {"binary_name": binary_name, "detail_level": "standard"},
                    )
                ).content[0].text
            )

            assert legacy.mode == "full"
            assert full.mode == "full"
            assert legacy.metadata.path == full.metadata.path
            assert legacy.statistics.total_functions == full.statistics.total_functions
            assert len(legacy.segments) == len(full.segments)
