# `cli/` — DEPRECATED

This directory is the upstream CLI subpackage. It still references the old `pyghidra_mcp_cli` /
`pyghidra-mcp` name and is **not** part of GhidraNexus today.

It will be deleted and replaced in **Phase 4 — CLI parity** with a new `python -m ghidra_nexus`
surface that talks directly to the same `Notebook` API the MCP tools use (no HTTP hop needed).

For now, run GhidraNexus commands through your MCP client (OpenCode, Claude Desktop, etc.).

See `../Implementations/phase-4-cli-parity.md` for the rewrite plan.
