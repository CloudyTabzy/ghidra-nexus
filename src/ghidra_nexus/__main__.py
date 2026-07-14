"""Package entry point.

``python -m ghidra_nexus`` routes to the notebook CLI when the first
non-option argument is a known CLI subcommand; otherwise it falls back to
the MCP server entry point (``ghidra_nexus.server:main``) so existing
``python -m ghidra_nexus --transport ...`` invocations keep working.
"""

import sys

from ghidra_nexus.cli import cli as _cli
from ghidra_nexus.server import main as _server_main

CLI_COMMANDS = frozenset(
    {
        "summary",
        "search",
        "get-decompile",
        "embed-status",
        "breadcrumbs",
        "aliases",
        "hypotheses",
        "rebuild-embeddings",
    }
)


def _first_positional(argv: list[str]) -> str | None:
    """Return the first positional (non-option, non-option-value) argument."""
    skip_next = False
    for arg in argv:
        if skip_next:
            skip_next = False
            continue
        if arg == "--":
            # Everything after -- is positional.
            continue
        if arg.startswith("-"):
            # Simple heuristic: if the option expects a value, skip the next token.
            # We cover the options our CLI group accepts; unknown flags are treated
            # as booleans, which errs on the side of server fallback (safe).
            if arg in ("--project-dir", "--project-name", "--notebook"):
                skip_next = True
            continue
        return arg
    return None


def main() -> None:
    argv = sys.argv[1:]
    first = _first_positional(argv)
    if first in CLI_COMMANDS:
        _cli()
    else:
        _server_main()


if __name__ == "__main__":
    main()
