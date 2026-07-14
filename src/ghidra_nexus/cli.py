"""GhidraNexus notebook CLI — no JVM, no HTTP, just SQLite.

This CLI operates directly on the persistent notebook (the same SQLite file the
MCP server writes to). It is read-only by default; the ``rebuild-embeddings``
subcommand mutates the embed queue so the background worker can pick it up.

Usage::

    python -m ghidra_nexus summary find.exe
    python -m ghidra_nexus search find.exe "allocate buffer" --mode hybrid --limit 10
    python -m ghidra_nexus get-decompile find.exe 0x1000 --limit 50
    python -m ghidra_nexus --json search find.exe "mutex" --mode hybrid
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import click
import numpy as np

from ghidra_nexus import __version__
from ghidra_nexus.notebook import Notebook
from ghidra_nexus.notebook.addresses import normalize_hex
from ghidra_nexus.notebook.pagination import (
    DEFAULT_LIMITS,
    clamp_limit,
    validate_offset,
    window_text,
)
from ghidra_nexus.notebook.search import hybrid_search, search_fts, search_vec
from ghidra_nexus.project_spec import DEFAULT_PROJECT_NAME, ProjectSpec

DEFAULT_PROJECT_DIR = "C:/Dev/Ghidra-MCP/ghidra-projects"


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _print_json(data: Any) -> None:
    click.echo(json.dumps(data, indent=2, default=str))


def _print_text(lines: list[str]) -> None:
    for line in lines:
        click.echo(line)


def _page_meta(
    *,
    offset: int,
    limit: int,
    returned: int,
    total: int | None = None,
    has_more: bool | None = None,
    next_offset: int | None = None,
) -> dict[str, Any]:
    if has_more is None and total is not None:
        has_more = (offset + returned) < total
    if next_offset is None and has_more:
        next_offset = offset + returned
    return {
        "offset": offset,
        "limit": limit,
        "returned": returned,
        "total": total,
        "has_more": has_more,
        "next_offset": next_offset,
    }


# ---------------------------------------------------------------------------
# Notebook discovery
# ---------------------------------------------------------------------------


def _resolve_notebook_path(
    *,
    notebook: str | None,
    project_dir: str,
    project_name: str,
) -> Path:
    """Resolve the notebook SQLite path from CLI options / env / defaults."""
    if notebook:
        return Path(notebook).expanduser().resolve()

    env_path = os.environ.get("NEXUS_NOTEBOOK_PATH")
    if env_path:
        return Path(env_path).expanduser().resolve()

    project_path = Path(project_dir).expanduser().resolve()
    spec = ProjectSpec.from_cli(
        project_path,
        project_name,
        default_project_name=DEFAULT_PROJECT_NAME,
    )
    primary = spec.nexus_data_dir / "notebook.sqlite"
    if primary.exists():
        return primary

    # Legacy naming fallback ({project}-nexus vs {project}-ghidra-nexus).
    legacy = project_path / f"{project_name}-nexus" / "notebook.sqlite"
    if legacy.exists():
        return legacy

    # Return primary even if missing so the user gets a clear "not found" error.
    return primary


def _open_notebook(path: Path) -> Notebook:
    if not path.exists():
        raise click.ClickException(
            f"Notebook not found: {path}\n"
            "Hint: import a binary through the MCP server first, "
            "or pass --notebook / --project-dir / --project-name."
        )
    return Notebook.open(path)


# ---------------------------------------------------------------------------
# Embedder helpers (lazy, best-effort)
# ---------------------------------------------------------------------------


def _encode_query(query: str) -> np.ndarray | None:
    """Encode a query string for semantic search. Returns None if vec unavailable."""
    from ghidra_nexus.notebook.embedder import get_embedder

    embedder = get_embedder()
    return embedder.encode(query)


def _require_vec(nb: Notebook, mode: str, fallback_fts: bool) -> bool:
    """Return True if vec is available; otherwise exit or fall back to FTS."""
    if nb.vec_available:
        return True
    if mode in ("semantic", "hybrid"):
        if fallback_fts:
            click.echo(
                "warning: sqlite-vec unavailable; falling back to FTS-only search.",
                err=True,
            )
            return False
        raise click.ClickException(
            "sqlite-vec is not available. "
            "Install `sqlite-vec` or set SQLITE_VEC_PATH. "
            "Use --fallback-fts to search with FTS only, or use --mode literal."
        )
    return False


# ---------------------------------------------------------------------------
# Shared CLI group
# ---------------------------------------------------------------------------


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=False,
)
@click.version_option(__version__, "-v", "--version", prog_name="ghidra-nexus")
@click.option(
    "--project-dir",
    type=click.Path(path_type=Path),
    default=DEFAULT_PROJECT_DIR,
    show_default=True,
    help="Directory containing the Ghidra project.",
)
@click.option(
    "--project-name",
    type=str,
    default=DEFAULT_PROJECT_NAME,
    show_default=True,
    help="Ghidra project name.",
)
@click.option(
    "--notebook",
    type=click.Path(path_type=Path),
    default=None,
    help="Direct path to notebook.sqlite (overrides project discovery).",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit machine-readable JSON including pagination metadata.",
)
@click.option(
    "--fallback-fts",
    is_flag=True,
    help="If semantic/hybrid search requested but vec unavailable, fall back to FTS.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    project_dir: Path,
    project_name: str,
    notebook: Path | None,
    as_json: bool,
    fallback_fts: bool,
) -> None:
    """GhidraNexus notebook CLI - query the knowledge plane without Ghidra/JVM."""
    ctx.ensure_object(dict)
    ctx.obj["notebook_path"] = _resolve_notebook_path(
        notebook=str(notebook) if notebook else None,
        project_dir=str(project_dir),
        project_name=project_name,
    )
    ctx.obj["as_json"] = as_json
    ctx.obj["fallback_fts"] = fallback_fts


def _nb_from_ctx(ctx: click.Context) -> Notebook:
    return _open_notebook(ctx.obj["notebook_path"])


def _is_json(ctx: click.Context) -> bool:
    return bool(ctx.obj.get("as_json"))


def _fmt_rva(addr: str) -> str:
    try:
        return normalize_hex(addr)
    except ValueError:
        return addr


def _run_search(
    nb: Notebook,
    bid: int,
    query: str,
    mode: str,
    offset: int,
    limit: int,
    fallback_fts: bool,
) -> tuple[list[dict], str]:
    """Execute one search mode and return (hits, backend)."""
    vec_enabled = _require_vec(nb, mode, fallback_fts)
    query_vec: np.ndarray | None = None
    if mode in ("semantic", "hybrid") and vec_enabled:
        query_vec = _encode_query(query)
        if query_vec is None and mode == "semantic":
            if fallback_fts:
                click.echo("warning: embedder failed; falling back to FTS.", err=True)
            else:
                raise click.ClickException(
                    "Embedder failed to encode the query. "
                    "Use --fallback-fts to search with FTS only, or use --mode literal."
                )

    if mode == "literal":
        hits = search_fts(nb.conn, query, binary_id=bid, limit=limit, offset=offset)
        backend = "fts_only"
    elif mode == "semantic":
        if query_vec is None or not vec_enabled:
            hits = search_fts(nb.conn, query, binary_id=bid, limit=limit, offset=offset)
            backend = "fts_only"
        else:
            hits = search_vec(nb.conn, query_vec, binary_id=bid, limit=limit)
            backend = "sqlite_vec"
    else:  # hybrid
        result = hybrid_search(
            nb.conn,
            query,
            query_vec if vec_enabled else None,
            binary_id=bid,
            limit=limit,
            offset=offset,
            vec_available=vec_enabled,
        )
        hits = result["results"]
        backend = result["backend"]

    return hits, backend


def _enrich_hits(nb: Notebook, bid: int, hits: list[dict]) -> list[dict]:
    """Pull missing summaries/entities from artifact_views."""
    enriched = []
    for h in hits:
        row = dict(h)
        rva = row.get("rva") or ""
        if rva and not row.get("function_name"):
            view = nb.views.get_for(bid, rva, row.get("kind", "decompile"))
            if view:
                row["summary"] = row.get("summary") or view.get("summary")
                try:
                    row["key_entities"] = json.loads(view.get("key_entities") or "[]")
                except json.JSONDecodeError:
                    row["key_entities"] = []
        enriched.append(row)
    return enriched


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


@cli.command("summary")
@click.argument("binary_name", required=False)
@click.pass_context
def summary_cmd(ctx: click.Context, binary_name: str | None) -> None:
    """Show cached counts and vec readiness for one or all binaries."""
    nb = _nb_from_ctx(ctx)

    if binary_name:
        b = nb.binaries.get(binary_name)
        if not b:
            raise click.ClickException(f"Binary {binary_name!r} not found in notebook.")
        bid = b["id"]
        data = {
            "binary_name": b["name"],
            "sha256": b["sha256"],
            "binary_class": b["binary_class"],
            "analysis_ready": bool(b["analysis_ready"]),
            "function_count": b["function_count"],
            "cached_decompiles": nb.decompiles.count_for_binary(bid),
            "cached_disassemblies": nb.disassemblies.count_for_binary(bid),
            "artifact_views": nb.views.count_for_binary(bid),
            "embeddings": nb.embeddings.count_for_binary(bid),
            "aliases": len(nb.aliases.list(bid)),
            "breadcrumbs_24h": len(nb.breadcrumbs.recent(limit=9999)),
            "vec_available": nb.vec_available,
            "vec_index_complete": bool(b.get("vec_index_complete", 0)),
            "embed_progress": b.get("embed_progress", 0),
            "embed_target": b.get("embed_target", 0),
            "embed_model": b.get("embed_model"),
            "reliability_notes": b.get("reliability_notes"),
        }
        if _is_json(ctx):
            _print_json(data)
            return
        lines = [
            f"binary:        {data['binary_name']}",
            f"sha256:        {data['sha256']}",
            f"class:         {data['binary_class']}",
            f"analysis:      {'ready' if data['analysis_ready'] else 'not ready'}",
            f"functions:     {data['function_count']}",
            f"decompiles:    {data['cached_decompiles']}",
            f"disassemblies: {data['cached_disassemblies']}",
            f"views:         {data['artifact_views']}",
            f"embeddings:    {data['embeddings']}",
            f"aliases:       {data['aliases']}",
            f"vec:           {'available' if data['vec_available'] else 'unavailable'}",
            f"vec_complete:  {data['vec_index_complete']}",
            f"embed:         {data['embed_progress']}/{data['embed_target']}",
        ]
        if data["reliability_notes"]:
            lines.append(f"notes:         {data['reliability_notes']}")
        _print_text(lines)
        return

    rows = []
    for b in nb.binaries.all():
        bid = b["id"]
        rows.append(
            {
                "name": b["name"],
                "class": b["binary_class"],
                "functions": b["function_count"],
                "decompiles": nb.decompiles.count_for_binary(bid),
                "views": nb.views.count_for_binary(bid),
                "embeddings": nb.embeddings.count_for_binary(bid),
                "vec_complete": bool(b.get("vec_index_complete", 0)),
            }
        )
    if _is_json(ctx):
        _print_json({"binaries": rows})
        return
    if not rows:
        click.echo("No binaries in notebook.")
        return
    header = f"{'name':<20} {'class':<12} {'funcs':>6} {'decomp':>6} {'views':>6} {'vec':>5}"
    lines = [header, "-" * len(header)]
    for r in rows:
        lines.append(
            f"{r['name']:<20} {r['class']:<12} {r['functions']:>6} "
            f"{r['decompiles']:>6} {r['views']:>6} {'yes' if r['vec_complete'] else 'no':>5}"
        )
    _print_text(lines)


@cli.command("search")
@click.argument("binary_name")
@click.argument("query")
@click.option(
    "--mode",
    type=click.Choice(["literal", "semantic", "hybrid"], case_sensitive=False),
    default="hybrid",
    show_default=True,
    help="Search backend. semantic/hybrid require sqlite-vec.",
)
@click.option("--offset", type=int, default=0, help="Result offset.")
@click.option("--limit", type=int, default=DEFAULT_LIMITS["fts"], help="Max results.")
@click.pass_context
def search_cmd(
    ctx: click.Context,
    binary_name: str,
    query: str,
    mode: str,
    offset: int,
    limit: int,
) -> None:
    """Search notebook views (FTS / semantic / hybrid)."""
    nb = _nb_from_ctx(ctx)
    b = nb.binaries.get(binary_name)
    if not b:
        raise click.ClickException(f"Binary {binary_name!r} not found in notebook.")
    bid = b["id"]

    limit = clamp_limit("fts", limit)
    offset = validate_offset("fts", offset)

    hits, backend = _run_search(
        nb, bid, query, mode, offset, limit, ctx.obj.get("fallback_fts", False)
    )
    enriched = _enrich_hits(nb, bid, hits)

    data = {
        "query": query,
        "mode": mode,
        "backend": backend,
        "vec_available": nb.vec_available,
        "vec_index_complete": bool(b.get("vec_index_complete", 0)),
        "results": enriched,
        "page": _page_meta(
            offset=offset, limit=limit, returned=len(enriched), total=len(hits)
        ),
    }

    if _is_json(ctx):
        _print_json(data)
        return

    if not enriched:
        click.echo(f"No results for {query!r} ({backend}).")
        return

    lines = [f"query: {query}  mode: {mode}  backend: {backend}  hits: {len(enriched)}"]
    for i, h in enumerate(enriched, start=offset + 1):
        rva = h.get("rva", "")
        name = h.get("name") or h.get("function_name") or ""
        kind = h.get("kind", "unknown")
        score = h.get("rrf_score") or h.get("score") or 0.0
        snippet = (h.get("snippet") or h.get("summary") or "").replace("\n", " ")[:200]
        lines.append(f"\n{i}. [{kind}] {name or rva} @ {rva}  score={score:.4f}")
        if snippet:
            lines.append(f"   {snippet}")
    _print_text(lines)


@cli.command("get-decompile")
@click.argument("binary_name")
@click.argument("rva")
@click.option("--offset", type=int, default=0, help="Line offset into the decompile.")
@click.option(
    "--limit",
    type=int,
    default=DEFAULT_LIMITS["decompile_lines"],
    help="Max lines to show.",
)
@click.pass_context
def get_decompile_cmd(
    ctx: click.Context,
    binary_name: str,
    rva: str,
    offset: int,
    limit: int,
) -> None:
    """Fetch a windowed decompile from the notebook cache."""
    nb = _nb_from_ctx(ctx)
    b = nb.binaries.get(binary_name)
    if not b:
        raise click.ClickException(f"Binary {binary_name!r} not found in notebook.")
    bid = b["id"]
    rva = _fmt_rva(rva)

    limit = clamp_limit("decompile_lines", limit)
    offset = validate_offset("decompile_lines", offset)

    cached = nb.decompiles.get(bid, rva)
    if not cached:
        raise click.ClickException(
            f"No cached decompile for {binary_name} @ {rva}. "
            "Run decompile_function through the MCP server first."
        )

    window = window_text(cached.get("code_text", ""), offset=offset, limit=limit)
    data = {
        "binary_name": binary_name,
        "rva": rva,
        "cached": True,
        "lines": cached.get("lines", 0),
        "code": window.text,
        "page": window.as_dict(),
    }

    if _is_json(ctx):
        _print_json(data)
        return

    start = window.offset
    end = window.offset + window.returned_lines
    click.echo(f"# {binary_name} @ {rva}  (lines {start}-{end} / {window.total_lines})")
    click.echo(data["code"], nl=False)
    if window.has_more:
        click.echo(f"\n# -- has_more: next_offset={window.next_offset}")


@cli.command("embed-status")
@click.argument("binary_name", required=False)
@click.pass_context
def embed_status_cmd(ctx: click.Context, binary_name: str | None) -> None:
    """Show embedding queue status and per-binary vec readiness."""
    nb = _nb_from_ctx(ctx)

    queue_counts = {
        r[0]: int(r[1])
        for r in nb.conn.execute(
            "SELECT status, COUNT(*) FROM embed_queue GROUP BY status"
        ).fetchall()
    }
    for k in ("pending", "done", "error", "skipped"):
        queue_counts.setdefault(k, 0)

    def _bin_summary(b: dict) -> dict:
        bid = b["id"]
        return {
            "name": b["name"],
            "class": b["binary_class"],
            "vec_available": nb.vec_available,
            "vec_status": b.get("vec_status", "unavailable"),
            "vec_index_complete": bool(b.get("vec_index_complete", 0)),
            "embed_progress": b.get("embed_progress", 0),
            "embed_target": b.get("embed_target", 0),
            "embed_model": b.get("embed_model"),
            "views_count": nb.views.count_for_binary(bid),
            "embeddings_count": nb.embeddings.count_for_binary(bid),
        }

    if binary_name:
        b = nb.binaries.get(binary_name)
        if not b:
            raise click.ClickException(f"Binary {binary_name!r} not found in notebook.")
        data = {
            "queue_counts": queue_counts,
            "binary": _bin_summary(b),
        }
    else:
        data = {
            "queue_counts": queue_counts,
            "binaries": [_bin_summary(b) for b in nb.binaries.all()],
        }

    if _is_json(ctx):
        _print_json(data)
        return

    lines = [
        f"queue: pending={queue_counts['pending']} done={queue_counts['done']} "
        f"error={queue_counts['error']} skipped={queue_counts['skipped']}",
        f"vec_available: {nb.vec_available}",
    ]
    targets = [data["binary"]] if binary_name else data["binaries"]
    for s in targets:
        lines.append(
            f"{s['name']:<20} {s['class']:<12} vec={s['vec_status']:<12} "
            f"embed={s['embed_progress']:>4}/{s['embed_target']:<4} "
            f"views={s['views_count']:>4} vecs={s['embeddings_count']:>4}"
        )
    _print_text(lines)


@cli.command("breadcrumbs")
@click.argument("binary_name", required=False)
@click.option("--session-id", type=str, default=None, help="Filter to a session id.")
@click.option("--offset", type=int, default=0, help="Result offset.")
@click.option("--limit", type=int, default=DEFAULT_LIMITS["breadcrumbs"], help="Max entries.")
@click.pass_context
def breadcrumbs_cmd(
    ctx: click.Context,
    binary_name: str | None,
    session_id: str | None,
    offset: int,
    limit: int,
) -> None:
    """Show recent tool-call breadcrumbs from the audit trail."""
    nb = _nb_from_ctx(ctx)
    bid = None
    if binary_name:
        b = nb.binaries.get(binary_name)
        if not b:
            raise click.ClickException(f"Binary {binary_name!r} not found in notebook.")
        bid = b["id"]

    limit = clamp_limit("breadcrumbs", limit)
    offset = validate_offset("breadcrumbs", offset)
    rows = nb.breadcrumbs.recent(binary_id=bid, session_id=session_id, limit=limit, offset=offset)

    data = {
        "breadcrumbs": rows,
        "page": _page_meta(offset=offset, limit=limit, returned=len(rows)),
    }
    if _is_json(ctx):
        _print_json(data)
        return

    if not rows:
        click.echo("No breadcrumbs.")
        return
    for r in rows:
        ts = r.get("ts", "")
        tool = r.get("tool", "")
        summary = (r.get("summary") or "").replace("\n", " ")[:120]
        click.echo(f"{ts}  {tool:<30} {summary}")


@cli.command("aliases")
@click.argument("binary_name")
@click.pass_context
def aliases_cmd(ctx: click.Context, binary_name: str) -> None:
    """List address aliases and tags for a binary."""
    nb = _nb_from_ctx(ctx)
    b = nb.binaries.get(binary_name)
    if not b:
        raise click.ClickException(f"Binary {binary_name!r} not found in notebook.")

    rows = nb.aliases.list(b["id"])
    if _is_json(ctx):
        _print_json({"aliases": rows})
        return

    if not rows:
        click.echo(f"No aliases for {binary_name}.")
        return
    header = f"{'rva':<16} {'name':<24} {'status':<12} tags"
    lines = [header, "-" * len(header)]
    for r in rows:
        tags = ", ".join(json.loads(r.get("tags") or "[]"))
        lines.append(
            f"{r.get('rva', ''):<16} {r.get('name', ''):<24} {r.get('status', '') or '':<12} {tags}"
        )
    _print_text(lines)


@cli.command("hypotheses")
@click.argument("binary_name", required=False)
@click.option(
    "--status", type=str, default=None, help="Filter by status (open/confirmed/rejected)."
)
@click.pass_context
def hypotheses_cmd(
    ctx: click.Context,
    binary_name: str | None,
    status: str | None,
) -> None:
    """List hypothesis-board entries for one or all binaries."""
    nb = _nb_from_ctx(ctx)
    bid = None
    if binary_name:
        b = nb.binaries.get(binary_name)
        if not b:
            raise click.ClickException(f"Binary {binary_name!r} not found in notebook.")
        bid = b["id"]

    rows = nb.hypotheses.list(binary_id=bid, status=status)
    if _is_json(ctx):
        _print_json({"hypotheses": rows})
        return

    if not rows:
        click.echo("No hypotheses.")
        return
    for r in rows:
        text = (r.get("text") or "").replace("\n", " ")[:140]
        click.echo(f"[{r.get('status', '')}] {text}")


def _rebuild_targets(nb: Notebook, binary_name: str | None) -> list[tuple[int, str]]:
    """Return (binary_id, name) tuples to rebuild."""
    if binary_name:
        b = nb.binaries.get(binary_name)
        if not b:
            raise click.ClickException(f"Binary {binary_name!r} not found in notebook.")
        return [(b["id"], b["name"])]
    return [(b["id"], b["name"]) for b in nb.binaries.all()]


def _enqueue_views(nb: Notebook, targets: list[tuple[int, str]]) -> int:
    """Drop old embeddings and enqueue every view. Returns number requeued."""
    from ghidra_nexus.notebook.vec import delete_vecs_for_binary

    total_requeued = 0
    for bid, name in targets:
        nb.embeddings.delete_for_binary(bid)
        try:
            delete_vecs_for_binary(nb.conn, bid)
        except Exception:
            pass
        nb.binaries.set_vec_status(
            name,
            vec_available=True,
            model=None,
            index_complete=False,
            progress=0,
            target=0,
        )
        for view in nb.conn.execute(
            "SELECT id FROM artifact_views WHERE binary_id = ?", (bid,)
        ).fetchall():
            nb.embed_queue.enqueue(int(view[0]))
            total_requeued += 1
    return total_requeued


def _run_foreground_worker(nb: Notebook, data: dict) -> None:
    """Start a blocking embed worker and add its stats to *data*."""
    from ghidra_nexus.notebook.embed_worker import EmbedWorker
    from ghidra_nexus.notebook.embedder import get_embedder

    worker = EmbedWorker(nb, get_embedder())
    worker.start()
    click.echo(
        "Foreground embed worker started; press Ctrl-C to stop after queue drains.",
        err=True,
    )
    try:
        import time

        while worker.running and nb.embed_queue.pending():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        worker.stop()
    data["worker_processed"] = worker._total_processed
    data["worker_errors"] = worker._total_errors


@cli.command("rebuild-embeddings")
@click.argument("binary_name", required=False)
@click.option(
    "--start-worker/--no-start-worker",
    default=False,
    help="Also start a foreground embed worker to drain the queue (default: just enqueue).",
)
@click.pass_context
def rebuild_embeddings_cmd(
    ctx: click.Context,
    binary_name: str | None,
    start_worker: bool,
) -> None:
    """Drop embeddings and re-enqueue every view for embedding."""
    nb = _nb_from_ctx(ctx)
    if not nb.vec_available:
        raise click.ClickException(
            "sqlite-vec is not available; cannot rebuild embeddings. "
            "Install `sqlite-vec` or set SQLITE_VEC_PATH."
        )

    targets = _rebuild_targets(nb, binary_name)
    total_requeued = _enqueue_views(nb, targets)

    data = {
        "rebuild_started": True,
        "binaries_affected": [name for _, name in targets],
        "views_requeued": total_requeued,
    }

    if start_worker:
        _run_foreground_worker(nb, data)

    if _is_json(ctx):
        _print_json(data)
        return

    click.echo(
        f"Requeued {total_requeued} views for {len(targets)} binary/ies: "
        f"{', '.join(data['binaries_affected']) or '(none)'}"
    )


def main() -> None:
    """Entry point used by ``python -m ghidra_nexus``."""
    cli()
