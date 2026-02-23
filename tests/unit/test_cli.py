"""Tests for CLI commands and flags."""

from typer.testing import CliRunner

from revgraph.cli.app import app

runner = CliRunner()


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "revgraph" in result.output


def test_help_shows_all_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ["extract", "load", "query", "embed", "analyze", "llm", "agent", "serve", "schema"]:
        assert cmd in result.output


def test_agent_help():
    result = runner.invoke(app, ["agent", "--help"])
    assert result.exit_code == 0
    assert "run" in result.output


def test_model_override_flag_in_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "--model" in result.output
