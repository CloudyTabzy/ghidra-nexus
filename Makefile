# GhidraNexus Makefile

.PHONY: help install install-dev run run-http test test-unit test-integration lint format clean check build notebook-init

help:
	@echo "GhidraNexus - Agent-first Ghidra MCP server with a persistent notebook"
	@echo ""
	@echo "Targets:"
	@echo "  install           Install project dependencies"
	@echo "  install-dev       Install with development dependencies"
	@echo "  run               Start the MCP server (stdio transport)"
	@echo "  run-http          Start on streamable-http at 127.0.0.1:8000"
	@echo "  test-unit         Run unit tests"
	@echo "  test-integration  Run integration tests (needs Ghidra)"
	@echo "  lint              Check code style with ruff"
	@echo "  format            Format code with ruff"
	@echo "  notebook-init     Initialize the notebook database for the default project"
	@echo "  build             Build distribution packages"
	@echo "  clean             Clean build artifacts and caches"

install:
	uv sync

install-dev:
	uv sync --extra dev

run:
	uv run ghidra-nexus

run-http:
	uv run ghidra-nexus --transport streamable-http --host 127.0.0.1 --port 8000

test-unit:
	uv run pytest tests/unit/ -v

test-integration:
	uv run pytest tests/integration/ -v

lint:
	uv run ruff check src/ tests/

format:
	uv run ruff format src/ tests/
	uv run ruff check --fix src/ tests/

check: lint test-unit
	@echo "All checks passed."

clean:
	rm -rf build/ dist/ *.egg-info/
	rm -rf .pytest_cache/ .coverage .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

build:
	uv build

# Phase-1: open the notebook SQLite at the default project path. Prints schema version,
# table list, binary count, and vec status.
notebook-init:
	uv run python -c "from ghidra_nexus.notebook import Notebook; p='ghidra_nexus_projects/my_project-nexus/notebook.sqlite'; nb=Notebook.open(p); print('path:', nb.cfg.path); print('user_version:', nb._user_version()); print('vec_available:', nb.vec_available); print('binaries:', nb.binaries.count()); nb.close()"
