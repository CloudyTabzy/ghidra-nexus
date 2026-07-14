"""Integration tests for Phase 5 — full knowledge-plane E2E.

These tests need a working Ghidra install and are skipped if
:envvar:`GHIDRA_INSTALL_DIR` is not set. They exercise the notebook cache,
sqlite-vec hybrid search, breadcrumbs, and the notebook CLI end-to-end.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ghidra_nexus.context import PyGhidraContext
from ghidra_nexus.models import (
    CodeSearchResults,
    DecompiledFunction,
    SurveyBinaryResult,
)

pytestmark = pytest.mark.skipif(
    not os.environ.get("GHIDRA_INSTALL_DIR"),
    reason="GHIDRA_INSTALL_DIR not set; skipping Ghidra integration tests",
)


@pytest.fixture(scope="module")
def find_exe_path():
    """Small Windows binary for a fast integration smoke test."""
    p = Path("C:/Windows/System32/find.exe")
    if not p.exists():
        pytest.skip("find.exe not available at C:/Windows/System32")
    return str(p)


@pytest.fixture(scope="module")
def phase5_project_root(tmp_path_factory):
    """Isolated project directory for the Phase 5 module."""
    return tmp_path_factory.mktemp("phase5-e2e-projects")


@pytest.fixture(scope="module")
def phase5_project_args(phase5_project_root):
    project_path = phase5_project_root / "phase5_e2e"
    project_name = "phase5_e2e_project"
    return [
        "--project-path",
        str(project_path),
        "--project-name",
        project_name,
    ]


@pytest.fixture(scope="module")
def server_params(find_exe_path, ghidra_env, phase5_project_args):
    """Server parameters with no command-line binary.

    The test explicitly imports ``find.exe`` and polls
    ``list_project_binaries`` until analysis completes. This mirrors the
    working pattern in the other integration tests and avoids the shutdown
    race observed with ``--no-threaded``.
    """
    # Cap the JVM heap so a memory-pressured test host still has native
    # memory left for Ghidra's analysis and PDB symbol handling.
    env = dict(ghidra_env)
    env.setdefault("JAVA_TOOL_OPTIONS", "-Xmx1536m")
    return StdioServerParameters(
        command="python",
        args=[
            "-m",
            "ghidra_nexus",
            *phase5_project_args,
            "--wait-for-analysis",
        ],
        env=env,
    )


@pytest.fixture(scope="module")
def notebook_path(phase5_project_args):
    """Resolve the notebook SQLite path the server will write to."""
    from ghidra_nexus.project_spec import ProjectSpec

    project_path = Path(phase5_project_args[1])
    project_name = phase5_project_args[3]
    spec = ProjectSpec.from_cli(project_path, project_name)
    return spec.nexus_data_dir / "notebook.sqlite"


def _run_cli(args: list[str], ghidra_env: dict) -> subprocess.CompletedProcess:
    """Invoke the notebook CLI as a subprocess and return the result."""
    return subprocess.run(
        [sys.executable, "-m", "ghidra_nexus", *args],
        capture_output=True,
        text=True,
        env=ghidra_env,
        check=False,
    )


def _find_binary_in_list_response(response, binary_name):
    """Locate a binary by generated name in a list_project_binaries response."""
    text_content = response.content[0].text
    program_infos = json.loads(text_content)["programs"]
    for program in program_infos:
        if binary_name in program["name"]:
            return program
    return None


@pytest.mark.asyncio
async def test_full_session_knowledge_plane(
    server_params,
    find_exe_path,
    ghidra_env,
    notebook_path,
):
    """Phase 5 end-to-end knowledge-plane session.

    Flow:
      import -> poll list_project_binaries -> section_health -> discover a
      function via survey_binary -> decompile (cached=false) -> decompile again
      (cached=true) -> notebook_summary (artifact_views > 0) -> wait for embed
      queue drain -> search_code hybrid -> notebook_breadcrumbs -> CLI summary +
      CLI search.

    Note: the Phase 5 spec also mentions an ``analyze_function dossier`` step.
    That tool is not yet in the catalog; ``notebook_summary`` covers the same
    per-function/per-binary dossier role here.
    """
    binary_name = PyGhidraContext._gen_unique_bin_name(find_exe_path)

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1. Import the binary explicitly.
            import_response = await session.call_tool(
                "import_binary", {"binary_path": find_exe_path}
            )
            import_content = import_response.content[0].text
            import_data = json.loads(import_content)
            assert import_data["queued_count"] == 1
            assert import_data["binary_name"] == binary_name

            # 2. Poll until analysis completes.
            ready = False
            function_count = 0
            for i in range(240):
                await asyncio.sleep(1)
                list_response = await session.call_tool("list_project_binaries", {})
                program = _find_binary_in_list_response(list_response, binary_name)
                if program and program.get("analysis_complete"):
                    ready = True
                    function_count = program.get("function_count", 0)
                    break
                if i % 10 == 0:
                    print(f"[test] waiting for analysis... {i}s")
            assert ready, f"Binary {binary_name} did not complete analysis"
            assert function_count > 0, "expected at least one function"

            # 3. section_health should return classified sections.
            section_response = await session.call_tool(
                "section_health", {"binary_name": binary_name}
            )
            sections = json.loads(section_response.content[0].text)
            # FastMCP unwraps single-element lists into the bare element, so
            # accept either a list or a lone dict and normalize.
            if isinstance(sections, dict):
                sections = [sections]
            assert isinstance(sections, list)
            assert len(sections) > 0
            for sec in sections:
                assert "name" in sec
                assert "classification" in sec
                assert "recommendation" in sec
                assert "entropy" in sec

            # 4. Discover a function to decompile via survey_binary.
            survey_response = await session.call_tool(
                "survey_binary", {"binary_name": binary_name, "detail_level": "standard"}
            )
            survey = SurveyBinaryResult.model_validate_json(survey_response.content[0].text)
            assert survey.ok is True
            assert survey.interesting_functions
            target_name = survey.interesting_functions[0].name
            assert target_name

            # 5. First decompile should come from Ghidra (cached=false).
            decompile_response = await session.call_tool(
                "decompile_function",
                {"binary_name": binary_name, "name_or_address": target_name, "limit": 50},
            )
            first_decompile = DecompiledFunction.model_validate_json(
                decompile_response.content[0].text
            )
            assert first_decompile.code, "decompile code must not be empty"
            assert first_decompile.cached is False

            # 6. Second decompile should be served from the notebook cache.
            cached_response = await session.call_tool(
                "decompile_function",
                {"binary_name": binary_name, "name_or_address": target_name, "limit": 50},
            )
            second_decompile = DecompiledFunction.model_validate_json(
                cached_response.content[0].text
            )
            assert second_decompile.cached is True
            assert second_decompile.code == first_decompile.code

            # 7. notebook_summary must report artifact_views > 0.
            summary_response = await session.call_tool(
                "notebook_summary", {"binary_name": binary_name}
            )
            summary = json.loads(summary_response.content[0].text)
            assert summary["binary_name"] == binary_name
            assert summary["function_count"] > 0
            assert summary["cached_decompiles"] >= 1
            assert summary["artifact_views"] >= 1

            # 8. Wait for the embed worker to drain the queue.
            vec_index_complete = False
            for i in range(120):
                embed_response = await session.call_tool(
                    "notebook_embed_status", {"binary_name": binary_name}
                )
                embed_status = json.loads(embed_response.content[0].text)
                queue_pending = embed_status.get("queue_counts", {}).get("pending", 0)
                vec_index_complete = bool(embed_status["binary"]["vec_index_complete"])
                if i % 10 == 0:
                    print(
                        f"[test] embed queue pending={queue_pending} "
                        f"vec_index_complete={vec_index_complete}"
                    )
                if queue_pending == 0 and (
                    vec_index_complete or not embed_status["binary"]["vec_available"]
                ):
                    break
                await asyncio.sleep(1)

            # 9. search_code hybrid should return at least one hit.
            search_term = "printf"
            search_response = await session.call_tool(
                "search_code",
                {
                    "binary_name": binary_name,
                    "query": search_term,
                    "search_mode": "hybrid",
                    "limit": 5,
                },
            )
            search_results = CodeSearchResults.model_validate_json(
                search_response.content[0].text
            )
            assert search_results.returned_count >= 1
            assert search_results.results[0].code
            assert search_results.backend in ("sqlite_vec", "fts_only", "hybrid")

            # 10. notebook_breadcrumbs should contain audit rows for our calls.
            breadcrumbs_response = await session.call_tool(
                "notebook_breadcrumbs", {"binary_name": binary_name, "limit": 100}
            )
            breadcrumbs = json.loads(breadcrumbs_response.content[0].text)
            assert isinstance(breadcrumbs, list)
            tool_names = {b.get("tool_name") for b in breadcrumbs}
            assert "decompile_function" in tool_names
            assert "section_health" in tool_names

    # 11. CLI summary should read the same notebook and report the binary.
    cli_project_dir = str(notebook_path.parent.parent)
    cli_project_name = notebook_path.parent.name.replace("-ghidra-nexus", "")
    cli_summary = _run_cli(
        [
            "--project-dir",
            cli_project_dir,
            "--project-name",
            cli_project_name,
            "summary",
            binary_name,
            "--json",
        ],
        ghidra_env,
    )
    assert cli_summary.returncode == 0, cli_summary.stderr
    cli_summary_data = json.loads(cli_summary.stdout)
    assert cli_summary_data["binary_name"] == binary_name
    assert cli_summary_data["function_count"] > 0

    # 12. CLI search should find the function in the notebook.
    cli_search = _run_cli(
        [
            "--project-dir",
            cli_project_dir,
            "--project-name",
            cli_project_name,
            "search",
            binary_name,
            search_term,
            "--mode",
            "hybrid",
            "--json",
        ],
        ghidra_env,
    )
    assert cli_search.returncode == 0, cli_search.stderr
    cli_search_data = json.loads(cli_search.stdout)
    assert cli_search_data["returned_count"] >= 1
    assert cli_search_data["backend"] in ("sqlite_vec", "fts_only", "hybrid")

    # Sanity: the notebook file actually exists on disk.
    assert notebook_path.exists(), f"notebook not found at {notebook_path}"
