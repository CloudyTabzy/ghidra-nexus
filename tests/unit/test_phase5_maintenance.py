"""Phase 5 notebook maintenance tools: archive breadcrumbs and vacuum."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from ghidra_nexus.mcp_tools import notebook_archive_breadcrumbs, notebook_vacuum


def _fresh_context():
    ctx = Mock()
    ctx.request_context.lifespan_context = Mock()
    return ctx


@pytest.mark.asyncio
async def test_archive_breadcrumbs_archives_and_deletes_old_crumbs():
    from ghidra_nexus.mcp_tools import _get_notebook

    ctx = _fresh_context()
    nb = await _get_notebook()
    bid = nb.binaries.upsert(name="sample.exe", sha256="a" * 64)

    # Insert a fresh and an old crumb.
    nb.breadcrumbs.insert(binary_id=bid, session_id="s1", tool="t1", summary="fresh")
    nb.conn.execute(
        "UPDATE breadcrumbs SET ts = datetime('now', '-60 days') WHERE summary = ?",
        ("fresh",),
    )
    nb.breadcrumbs.insert(binary_id=bid, session_id="s1", tool="t2", summary="old")
    nb.conn.execute(
        "UPDATE breadcrumbs SET ts = datetime('now', '-60 days') WHERE summary = ?",
        ("old",),
    )

    response = await notebook_archive_breadcrumbs(ctx, binary_name="sample.exe", age_days=30)
    assert response["binary_name"] == "sample.exe"
    assert response["archived"] == 2
    assert response["deleted"] == 2

    remaining = nb.conn.execute("SELECT COUNT(*) FROM breadcrumbs").fetchone()[0]
    archived = nb.conn.execute("SELECT COUNT(*) FROM breadcrumbs_archive").fetchone()[0]
    assert remaining == 0
    assert archived == 2


@pytest.mark.asyncio
async def test_archive_breadcrumbs_respects_session_filter():
    from ghidra_nexus.mcp_tools import _get_notebook

    ctx = _fresh_context()
    nb = await _get_notebook()
    bid = nb.binaries.upsert(name="sample.exe", sha256="a" * 64)

    for sid in ("keep", "drop"):
        nb.breadcrumbs.insert(binary_id=bid, session_id=sid, tool="t", summary=sid)
        nb.conn.execute(
            "UPDATE breadcrumbs SET ts = datetime('now', '-60 days') WHERE summary = ?",
            (sid,),
        )

    response = await notebook_archive_breadcrumbs(
        ctx, binary_name="sample.exe", session_id="drop", age_days=30
    )
    assert response["archived"] == 1
    assert response["deleted"] == 1
    assert response["session_id"] == "drop"

    rows = nb.conn.execute("SELECT session_id FROM breadcrumbs").fetchall()
    assert [r[0] for r in rows] == ["keep"]


@pytest.mark.asyncio
async def test_vacuum_deletes_old_generations():
    from ghidra_nexus.mcp_tools import _get_notebook

    ctx = _fresh_context()
    nb = await _get_notebook()
    bid = nb.binaries.upsert(name="sample.exe", sha256="a" * 64)

    # Three generations for the same RVA.
    for gen in (0, 1, 2):
        nb.decompiles.put(
            binary_id=bid, rva="0x1000", code=f"gen{gen}", lines=1,
            analysis_generation=gen,
        )
        nb.disassemblies.put(
            binary_id=bid, rva="0x1000", asm=f"gen{gen}", instruction_count=1,
            analysis_generation=gen,
        )

    response = await notebook_vacuum(ctx, binary_name="sample.exe", keep_generations=2)
    assert response["binaries_affected"] == ["sample.exe"]
    assert response["decompiles_deleted"] == 1
    assert response["disassemblies_deleted"] == 1
    assert response["keep_generations"] == 2
    assert "VACUUM not run" in response["vacuum_note"]

    decomp_gens = {
        r[0]
        for r in nb.conn.execute(
            "SELECT analysis_generation FROM decompiles WHERE binary_id = ?", (bid,)
        ).fetchall()
    }
    assert decomp_gens == {1, 2}


@pytest.mark.asyncio
async def test_vacuum_can_run_vacuum():
    from ghidra_nexus.mcp_tools import _get_notebook

    ctx = _fresh_context()
    nb = await _get_notebook()
    nb.binaries.upsert(name="sample.exe", sha256="a" * 64)

    response = await notebook_vacuum(ctx, binary_name="sample.exe", run_vacuum=True)
    assert "completed successfully" in response["vacuum_note"]


@pytest.mark.asyncio
async def test_vacuum_rejects_zero_keep_generations():
    from ghidra_nexus.mcp_tools import _get_notebook

    ctx = _fresh_context()
    nb = await _get_notebook()
    nb.binaries.upsert(name="sample.exe", sha256="a" * 64)

    response = await notebook_vacuum(ctx, binary_name="sample.exe", keep_generations=0)
    assert response["ok"] is False
    assert response["error_code"] == "invalid_params"
