__version__ = "0.3.0"
__author__ = "CloudyTabzy"
__project__ = "GhidraNexus"
__description__ = "Agent-first Ghidra MCP server with a persistent notebook."


def main() -> None:
    """Main entry point for the package."""
    from .server import main as _main

    _main()


_LAZY_MODULES: dict[str, str] = {
    "server": "ghidra_nexus.server",
    "PyGhidraContext": "ghidra_nexus.context",
    "ProgramInfo": "ghidra_nexus.context",
    "GhidraTools": "ghidra_nexus.tools",
}


def __getattr__(name: str):
    """Lazy-load heavy submodules to avoid pulling in chromadb/pyghidra at import time.

    Implementation note: we use ``sys.modules.get()`` instead of ``from . import server``
    so a partial-package import state doesn't recurse via ``__getattr__`` itself. The
    previous implementation hit a ``RecursionError`` whenever a sibling submodule did
    ``from ghidra_nexus import server`` (which is the natural form inside server.py's
    companions). Touching ``sys.modules`` directly short-circuits the recursion.
    """
    import sys as _sys

    fullname = _LAZY_MODULES.get(name)
    if fullname is None:
        if name == "Notebook":
            # Phase-1 surface; surface a clear error until the notebook ships.
            raise AttributeError(
                "ghidra_nexus.Notebook is not yet implemented (Phase 1+ in "
                "Implementations/phase-1-foundation.md)."
            )
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    mod = _sys.modules.get(fullname)
    if mod is not None:
        return mod
    import importlib

    mod = importlib.import_module(fullname)
    _sys.modules[__name__].__dict__[name] = mod  # cache on the package
    return mod


__all__ = [
    "GhidraTools",
    "ProgramInfo",
    "PyGhidraContext",
    "Notebook",
    "main",
    "server",
    "__version__",
    "__author__",
    "__project__",
    "__description__",
]
