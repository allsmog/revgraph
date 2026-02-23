"""revgraph query — execute Cypher or natural language queries."""

from __future__ import annotations

from typing import Optional

import typer


def query_cmd(
    query: Optional[str] = typer.Argument(None, help="Query string (Cypher or natural language)"),
    cypher: bool = typer.Option(False, "--cypher", "-c", help="Interpret query as raw Cypher"),
    natural: bool = typer.Option(False, "--natural", "-n", help="Translate NL to Cypher via LLM"),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Interactive query session"),
    explain: bool = typer.Option(False, "--explain", help="Show generated Cypher before executing"),
    limit: int = typer.Option(50, "--limit", "-l", help="Max rows to return"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Query the Neo4j graph database."""
    from revgraph.cli.app import get_context
    from revgraph.graph.query_engine import QueryEngine
    from revgraph.utils.formatters import print_table, print_json, print_error

    ctx = get_context()
    driver = ctx.ensure_neo4j()
    engine = QueryEngine(driver)

    if interactive:
        _run_interactive(ctx, engine, explain, limit, output_json)
        return

    if query is None:
        print_error("Provide a query or use --interactive")
        raise typer.Exit(1)

    if natural:
        from revgraph.nl2gql.translator import NL2CypherTranslator

        llm = ctx.ensure_llm()
        translator = NL2CypherTranslator(llm, driver)
        cypher_query = translator.translate(query)
        if explain:
            typer.echo(f"Generated Cypher:\n  {cypher_query}\n")
    elif cypher:
        cypher_query = query
    else:
        # Auto-detect: if it looks like Cypher, treat as Cypher
        upper = query.strip().upper()
        if any(upper.startswith(kw) for kw in ("MATCH", "CREATE", "RETURN", "CALL", "WITH")):
            cypher_query = query
        else:
            from revgraph.nl2gql.translator import NL2CypherTranslator

            llm = ctx.ensure_llm()
            translator = NL2CypherTranslator(llm, driver)
            cypher_query = translator.translate(query)
            if explain:
                typer.echo(f"Generated Cypher:\n  {cypher_query}\n")

    results = engine.execute(cypher_query, limit=limit)

    if output_json:
        print_json(results)
    else:
        print_table(results)


def _run_interactive(ctx, engine, explain: bool, limit: int, output_json: bool) -> None:
    """Interactive REPL for queries."""
    from rich.prompt import Prompt
    from revgraph.utils.formatters import print_table, print_json, print_error, console

    console.print("[bold]RevGraph Query Shell[/bold] (type 'exit' to quit)")
    console.print("Prefix with '!' for natural language, otherwise treated as Cypher\n")

    while True:
        try:
            raw = Prompt.ask("[bold cyan]revgraph[/bold cyan]")
        except (KeyboardInterrupt, EOFError):
            break

        raw = raw.strip()
        if not raw or raw.lower() in ("exit", "quit", "q"):
            break

        try:
            if raw.startswith("!"):
                from revgraph.nl2gql.translator import NL2CypherTranslator

                llm = ctx.ensure_llm()
                translator = NL2CypherTranslator(llm, engine._driver)
                cypher_query = translator.translate(raw[1:].strip())
                if explain:
                    console.print(f"[dim]Cypher: {cypher_query}[/dim]\n")
            else:
                cypher_query = raw

            results = engine.execute(cypher_query, limit=limit)
            if output_json:
                print_json(results)
            else:
                print_table(results)
        except Exception as exc:
            print_error(str(exc))
