"""revgraph schema — graph schema management."""

from __future__ import annotations

import typer

schema_app = typer.Typer(no_args_is_help=True)


@schema_app.command()
def create() -> None:
    """Create graph schema (constraints, indexes)."""
    from revgraph.cli.app import get_context
    from revgraph.graph.schema import create_schema
    from revgraph.utils.formatters import print_success

    ctx = get_context()
    driver = ctx.ensure_neo4j()
    create_schema(driver)
    print_success("Schema created successfully")


@schema_app.command()
def drop() -> None:
    """Drop all graph schema elements."""
    from revgraph.cli.app import get_context
    from revgraph.graph.schema import drop_schema
    from revgraph.utils.formatters import print_success, print_warning

    print_warning("This will drop all constraints and indexes!")
    confirm = typer.confirm("Continue?")
    if not confirm:
        raise typer.Abort()

    ctx = get_context()
    driver = ctx.ensure_neo4j()
    drop_schema(driver)
    print_success("Schema dropped")


@schema_app.command()
def show() -> None:
    """Show current graph schema."""
    from revgraph.cli.app import get_context
    from revgraph.graph.schema import show_schema
    from revgraph.utils.formatters import console

    ctx = get_context()
    driver = ctx.ensure_neo4j()
    info = show_schema(driver)
    console.print(info)
