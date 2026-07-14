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
    "Notebook": "CLASS:ghidra_nexus.notebook",
}


def __getattr__(name: str):
    """Lazy-load heavy submodules or classes to avoid pulling in chromadb/pyghidra
    at import time.

    Entries in ``_LAZY_MODULES`` whose value starts with ``CLASS:`` are treated as
    class-level exports (e.g. ``Notebook`` → the :class:`~ghidra_nexus.notebook.Notebook`
    class). Otherwise the value is treated as a module fullname and the *module* is
    returned.
    """
    import sys as _sys

    spec = _LAZY_MODULES.get(name)
    if spec is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    if spec.startswith("CLASS:"):
        module_name = spec.removeprefix("CLASS:")
        mod = _sys.modules.get(module_name)
        if mod is None:
            import importlib

            mod = importlib.import_module(module_name)
        # The class name is ``name`` by convention — import it.
        try:
            value = getattr(mod, name)
        except AttributeError as e:
            raise AttributeError(
                f"ghidra_nexus: lazy class {name!r} not found in {module_name}"
            ) from e
        _sys.modules[__name__].__dict__[name] = value
        return value

    # Module-level lazy import (current convention).
    mod = _sys.modules.get(spec)
    if mod is not None:
        return mod
    import importlib

    mod = importlib.import_module(spec)
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
