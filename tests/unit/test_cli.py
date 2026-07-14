"""Unit tests for the GhidraNexus notebook CLI (Phase 4).

These tests never touch Ghidra/JVM — they create a temporary notebook,
seed it with cache data, and exercise the click CLI surface.
"""

from __future__ import annotations

import json
from pathlib import Path

import click.testing
import pytest

from ghidra_nexus import __main__ as main_mod, cli as cli_mod
from ghidra_nexus.notebook import Notebook
from ghidra_nexus.notebook.cache import (
    write_decompile_cache,
    write_strings_cache,
    write_xrefs_cache,
)
from ghidra_nexus.notebook.extractors.base import register
from ghidra_nexus.notebook.extractors.decompile import DecompileExtractor
from ghidra_nexus.notebook.extractors.families import (
    DisasmExtractor,
    SectionHealthExtractor,
    StringsExtractor,
    XrefsExtractor,
)
from ghidra_nexus.notebook.vec import VecStatus


@pytest.fixture
def runner() -> click.testing.CliRunner:
    return click.testing.CliRunner()


@pytest.fixture
def nb_path(tmp_path: Path) -> Path:
    return tmp_path / "notebook.sqlite"


@pytest.fixture
def nb(nb_path: Path, monkeypatch: pytest.MonkeyPatch) -> Notebook:
    # Ensure extractor families are present (conftest usually does this, but
    # keep the test self-contained in case it runs in isolation).
    register(DecompileExtractor())
    register(DisasmExtractor())
    register(XrefsExtractor())
    register(StringsExtractor())
    register(SectionHealthExtractor())
    # Force FTS-only mode so these tests are independent of whether sqlite-vec
    # is installed in the active environment.
    monkeypatch.setattr(
        "ghidra_nexus.notebook.store.try_enable_vec",
        lambda _conn: VecStatus(available=False),
    )
    n = Notebook.open(nb_path)
    yield n
    n.close_quietly()


@pytest.fixture
def find_binary(nb: Notebook) -> int:
    """A seeded binary with a cached decompile, strings, and xrefs."""
    bid = nb.binaries.upsert(
        name="find.exe",
        sha256="a" * 64,
        image_base="0x400000",
        arch="x86_64",
        function_count=27,
    )
    write_decompile_cache(
        nb,
        binary_id=bid,
        binary_name="find.exe",
        binary_sha256="a" * 64,
        rva="0x1000",
        current_gen=0,
        result={
            "name": "main",
            "code": "int main() {\n  CreateFileW();\n  return 0;\n}\n",
            "lines": 4,
            "decompiler_status": "decompiled",
            "signature": "int main(void)",
        },
    )
    write_decompile_cache(
        nb,
        binary_id=bid,
        binary_name="find.exe",
        binary_sha256="a" * 64,
        rva="0x2000",
        current_gen=0,
        result={
            "name": "allocate_buffer",
            "code": "void *allocate_buffer(size_t n) {\n  return malloc(n);\n}\n",
            "lines": 3,
            "decompiler_status": "decompiled",
            "signature": "void *allocate_buffer(size_t)",
        },
    )
    write_strings_cache(
        nb,
        binary_id=bid,
        binary_name="find.exe",
        current_gen=0,
        result={"strings": [{"value": "password", "address": "0x5000", "encoding": "ascii"}]},
    )
    write_xrefs_cache(
        nb,
        binary_id=bid,
        binary_name="find.exe",
        rva="0x1000",
        current_gen=0,
        result={
            "cross_references": [
                {
                    "from_address": "0x2000",
                    "to_address": "0x1000",
                    "type": "code",
                    "function_name": "allocate_buffer",
                }
            ]
        },
    )
    nb.aliases.upsert(
        binary_id=bid,
        rva="0x1000",
        name="entry",
        tags=["important"],
        status="confirmed",
    )
    nb.hypotheses.create(text="main calls CreateFileW", binary_id=bid, status="open")
    nb.breadcrumbs.insert(
        binary_id=bid,
        session_id="test-session",
        tool="notebook_summary",
        summary="summary check",
    )
    nb.binaries.set_vec_status(
        "find.exe",
        vec_available=False,
        model=None,
        index_complete=False,
        progress=0,
        target=10,
    )
    return bid


# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------


def test_summary_single_binary(
    runner: click.testing.CliRunner,
    nb_path: Path,
    find_binary: int,
) -> None:
    result = runner.invoke(
        cli_mod.cli, ["--notebook", str(nb_path), "summary", "find.exe"]
    )
    assert result.exit_code == 0, result.output
    assert "find.exe" in result.output
    assert "decompiles:" in result.output


def test_summary_all_binaries(
    runner: click.testing.CliRunner,
    nb_path: Path,
    find_binary: int,
) -> None:
    result = runner.invoke(cli_mod.cli, ["--notebook", str(nb_path), "summary"])
    assert result.exit_code == 0, result.output
    assert "find.exe" in result.output


def test_summary_json(
    runner: click.testing.CliRunner,
    nb_path: Path,
    find_binary: int,
) -> None:
    result = runner.invoke(
        cli_mod.cli, ["--notebook", str(nb_path), "--json", "summary", "find.exe"]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["binary_name"] == "find.exe"
    assert data["cached_decompiles"] == 2


def test_summary_missing_binary(
    runner: click.testing.CliRunner,
    nb_path: Path,
    find_binary: int,
) -> None:
    result = runner.invoke(
        cli_mod.cli, ["--notebook", str(nb_path), "summary", "nope.exe"]
    )
    assert result.exit_code != 0
    assert "not found" in result.output


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------


def test_search_literal(
    runner: click.testing.CliRunner,
    nb_path: Path,
    find_binary: int,
) -> None:
    result = runner.invoke(
        cli_mod.cli,
        ["--notebook", str(nb_path), "search", "find.exe", "CreateFileW", "--mode", "literal"],
    )
    assert result.exit_code == 0, result.output
    assert "CreateFileW" in result.output or "main" in result.output


def test_search_json_backend(
    runner: click.testing.CliRunner,
    nb_path: Path,
    find_binary: int,
) -> None:
    result = runner.invoke(
        cli_mod.cli,
        [
            "--notebook",
            str(nb_path),
            "--json",
            "search",
            "find.exe",
            "CreateFileW",
            "--mode",
            "literal",
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["backend"] == "fts_only"
    assert "page" in data
    assert data["page"]["limit"] > 0


def test_search_hybrid_falls_back_to_fts(
    runner: click.testing.CliRunner,
    nb_path: Path,
    find_binary: int,
) -> None:
    result = runner.invoke(
        cli_mod.cli,
        [
            "--notebook",
            str(nb_path),
            "--fallback-fts",
            "search",
            "find.exe",
            "allocate",
            "--mode",
            "hybrid",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "allocate" in result.output.lower()


def test_search_semantic_without_vec_exits(
    runner: click.testing.CliRunner,
    nb_path: Path,
    find_binary: int,
) -> None:
    result = runner.invoke(
        cli_mod.cli,
        ["--notebook", str(nb_path), "search", "find.exe", "allocate", "--mode", "semantic"],
    )
    assert result.exit_code != 0
    assert "sqlite-vec" in result.output


# ---------------------------------------------------------------------------
# get-decompile
# ---------------------------------------------------------------------------


def test_get_decompile(
    runner: click.testing.CliRunner,
    nb_path: Path,
    find_binary: int,
) -> None:
    result = runner.invoke(
        cli_mod.cli,
        ["--notebook", str(nb_path), "get-decompile", "find.exe", "0x1000"],
    )
    assert result.exit_code == 0, result.output
    assert "CreateFileW" in result.output


def test_get_decompile_json_pagination(
    runner: click.testing.CliRunner,
    nb_path: Path,
    find_binary: int,
) -> None:
    result = runner.invoke(
        cli_mod.cli,
        [
            "--notebook",
            str(nb_path),
            "--json",
            "get-decompile",
            "find.exe",
            "0x1000",
            "--limit",
            "2",
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["page"]["limit"] == 2
    assert data["page"]["has_more"] is True


def test_get_decompile_missing_rva(
    runner: click.testing.CliRunner,
    nb_path: Path,
    find_binary: int,
) -> None:
    result = runner.invoke(
        cli_mod.cli,
        ["--notebook", str(nb_path), "get-decompile", "find.exe", "0x9999"],
    )
    assert result.exit_code != 0
    assert "No cached decompile" in result.output


# ---------------------------------------------------------------------------
# embed-status / breadcrumbs / aliases / hypotheses
# ---------------------------------------------------------------------------


def test_embed_status(
    runner: click.testing.CliRunner,
    nb_path: Path,
    find_binary: int,
) -> None:
    result = runner.invoke(
        cli_mod.cli, ["--notebook", str(nb_path), "embed-status", "find.exe"]
    )
    assert result.exit_code == 0, result.output
    assert "find.exe" in result.output


def test_breadcrumbs(
    runner: click.testing.CliRunner,
    nb_path: Path,
    find_binary: int,
) -> None:
    result = runner.invoke(
        cli_mod.cli, ["--notebook", str(nb_path), "breadcrumbs", "find.exe"]
    )
    assert result.exit_code == 0, result.output
    assert "notebook_summary" in result.output


def test_aliases(
    runner: click.testing.CliRunner,
    nb_path: Path,
    find_binary: int,
) -> None:
    result = runner.invoke(
        cli_mod.cli, ["--notebook", str(nb_path), "aliases", "find.exe"]
    )
    assert result.exit_code == 0, result.output
    assert "entry" in result.output
    assert "important" in result.output


def test_hypotheses(
    runner: click.testing.CliRunner,
    nb_path: Path,
    find_binary: int,
) -> None:
    result = runner.invoke(
        cli_mod.cli, ["--notebook", str(nb_path), "hypotheses", "find.exe"]
    )
    assert result.exit_code == 0, result.output
    assert "CreateFileW" in result.output


# ---------------------------------------------------------------------------
# rebuild-embeddings
# ---------------------------------------------------------------------------


def test_rebuild_embeddings_without_vec_fails(
    runner: click.testing.CliRunner,
    nb_path: Path,
    find_binary: int,
) -> None:
    result = runner.invoke(
        cli_mod.cli,
        ["--notebook", str(nb_path), "rebuild-embeddings", "find.exe"],
    )
    assert result.exit_code != 0
    assert "sqlite-vec" in result.output


# ---------------------------------------------------------------------------
# __main__ routing
# ---------------------------------------------------------------------------


def test_main_routes_to_cli_for_subcommand(monkeypatch) -> None:
    cli_called = []
    server_called = []
    monkeypatch.setattr(main_mod, "_cli", lambda: cli_called.append(True))
    monkeypatch.setattr(main_mod, "_server_main", lambda: server_called.append(True))

    monkeypatch.setattr(main_mod.sys, "argv", ["ghidra_nexus", "summary", "find.exe"])
    main_mod.main()
    assert cli_called
    assert not server_called


def test_main_routes_to_server_without_subcommand(monkeypatch) -> None:
    cli_called = []
    server_called = []
    monkeypatch.setattr(main_mod, "_cli", lambda: cli_called.append(True))
    monkeypatch.setattr(main_mod, "_server_main", lambda: server_called.append(True))

    monkeypatch.setattr(main_mod.sys, "argv", ["ghidra_nexus", "--transport", "stdio"])
    main_mod.main()
    assert server_called
    assert not cli_called


def test_main_routes_to_cli_with_options_before_command(monkeypatch) -> None:
    cli_called = []
    server_called = []
    monkeypatch.setattr(main_mod, "_cli", lambda: cli_called.append(True))
    monkeypatch.setattr(main_mod, "_server_main", lambda: server_called.append(True))

    monkeypatch.setattr(
        main_mod.sys,
        "argv",
        ["ghidra_nexus", "--project-dir", "/tmp/proj", "--json", "summary"],
    )
    main_mod.main()
    assert cli_called
    assert not server_called
