"""Root Typer application with subcommand registration."""

from __future__ import annotations

from typing import Optional

import typer

from revgraph import RevGraphContext, __version__

app = typer.Typer(
    name="revgraph",
    help="RevGraph — Reverse Engineering Graph Intelligence Toolkit",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

# Shared state across commands
_ctx = RevGraphContext()


def get_context() -> RevGraphContext:
    return _ctx


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"revgraph {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    config: Optional[str] = typer.Option(None, "--config", "-C", help="Path to revgraph.yaml"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Override LLM model (e.g. haiku, sonnet, opus)"),
    version: Optional[bool] = typer.Option(
        None, "--version", "-V", callback=_version_callback, is_eager=True
    ),
) -> None:
    """RevGraph — Reverse Engineering Graph Intelligence Toolkit."""
    from revgraph.config.loader import load_config
    from revgraph.utils.logging import setup_logging

    setup_logging(level="DEBUG" if verbose else "INFO")
    _ctx.config = load_config(config)
    if model:
        _ctx.model_override = model


# -- Subcommand registration --
from revgraph.cli.extract import extract_cmd  # noqa: E402
from revgraph.cli.load import load_cmd  # noqa: E402
from revgraph.cli.query import query_cmd  # noqa: E402
from revgraph.cli.embed import embed_cmd  # noqa: E402
from revgraph.cli.analyze import analyze_app  # noqa: E402
from revgraph.cli.llm_cmd import llm_app  # noqa: E402
from revgraph.cli.agent import agent_app  # noqa: E402
from revgraph.cli.serve import serve_cmd  # noqa: E402
from revgraph.cli.schema_cmd import schema_app  # noqa: E402
from revgraph.cli.analyze_bin import analyze_bin_cmd  # noqa: E402

app.command(name="extract")(extract_cmd)
app.command(name="load")(load_cmd)
app.command(name="query")(query_cmd)
app.command(name="embed")(embed_cmd)
app.add_typer(analyze_app, name="analyze", help="Analysis commands (bbr, cluster, similarity)")
app.add_typer(llm_app, name="llm", help="LLM tasks (summarize, label, vuln-report, yara)")
app.add_typer(agent_app, name="agent", help="Agent workflows")
app.command(name="serve")(serve_cmd)
app.add_typer(schema_app, name="schema", help="Graph schema management")
app.command(name="analyze-bin")(analyze_bin_cmd)
