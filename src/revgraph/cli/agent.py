"""revgraph agent — manage and run agent workflows."""

from __future__ import annotations

from typing import Optional

import typer

agent_app = typer.Typer(no_args_is_help=True)


@agent_app.command()
def run(
    workflow: str = typer.Argument(..., help="Workflow name (analysis, patch-impact, nday-triage, yara, firmware)"),
    input: Optional[str] = typer.Option(None, "--input", "-i", help="Input text or file path"),
    interactive: bool = typer.Option(False, "--interactive", help="Run in interactive mode"),
    max_turns: int = typer.Option(30, "--max-turns", help="Max agent conversation turns"),
) -> None:
    """Run an agent workflow."""
    import asyncio
    from revgraph.cli.app import get_context
    from revgraph.agents.teams import AgentTeamFactory
    from revgraph.utils.formatters import console, print_error

    ctx = get_context()
    cfg = ctx.ensure_config()
    driver = ctx.ensure_neo4j()
    llm = ctx.ensure_llm()

    factory = AgentTeamFactory(cfg, driver, llm)

    try:
        team = factory.create_team(workflow)
    except ValueError as exc:
        print_error(str(exc))
        raise typer.Exit(1)

    task_input = input or ""
    if not task_input and not interactive:
        print_error("Provide --input or use --interactive mode")
        raise typer.Exit(1)

    console.print(f"[bold]Running workflow: {workflow}[/bold]")
    console.print(f"[dim]Max turns: {max_turns}[/dim]\n")

    result = asyncio.run(team.run(task_input, max_turns=max_turns, interactive=interactive))
    console.print(f"\n[bold]Result:[/bold]\n{result}")


@agent_app.command(name="list")
def list_workflows() -> None:
    """List available agent workflows."""
    from revgraph.agents.teams import WORKFLOW_REGISTRY
    from revgraph.utils.formatters import print_table

    rows = [
        {"workflow": name, "description": meta["description"], "agents": ", ".join(meta["agents"])}
        for name, meta in WORKFLOW_REGISTRY.items()
    ]
    print_table(rows, title="Available Workflows")
