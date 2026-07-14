from pathlib import Path

import pytest

from ghidra_nexus.project_spec import DEFAULT_PROJECT_NAME, ProjectSpec


def test_project_spec_from_gpr_path():
    spec = ProjectSpec.from_cli(Path("/tmp/projects/sample.gpr"), DEFAULT_PROJECT_NAME)

    assert spec.was_gpr_path is True
    assert spec.project_directory == Path("/tmp/projects")
    assert spec.project_name == "sample"
    assert spec.gpr_path == Path("/tmp/projects/sample.gpr")
    assert spec.nexus_data_dir == Path("/tmp/projects/sample-ghidra-nexus")


def test_project_spec_rejects_project_name_with_gpr_path():
    with pytest.raises(ValueError, match="Cannot use --project-name"):
        ProjectSpec.from_cli(Path("/tmp/projects/sample.gpr"), "custom")


def test_project_spec_from_directory_path():
    spec = ProjectSpec.from_cli(Path("/tmp/projects"), "sample")

    assert spec.was_gpr_path is False
    assert spec.project_directory == Path("/tmp/projects")
    assert spec.project_name == "sample"
    assert spec.gpr_path == Path("/tmp/projects/sample.gpr")
    assert spec.nexus_data_dir == Path("/tmp/projects/sample-ghidra-nexus")


def test_gui_stdio_rejected_before_ghidra_start():
    import click.testing

    from ghidra_nexus.server import main

    runner = click.testing.CliRunner()
    result = runner.invoke(main, ["--gui", "--transport", "stdio"])

    assert result.exit_code != 0
    assert "--gui requires --transport streamable-http or --transport http" in result.output
