"""revgraph serve — start MCP servers."""

from __future__ import annotations

from typing import Optional

import typer


def serve_cmd(
    server: str = typer.Argument("all", help="Server to start: blackfyre|neo4j|embedding|all"),
    transport: str = typer.Option("stdio", "--transport", "-t", help="Transport: stdio|sse"),
    port: int = typer.Option(8080, "--port", "-p", help="Port for SSE transport"),
) -> None:
    """Start MCP server(s)."""
    from revgraph.cli.app import get_context
    from revgraph.utils.formatters import print_error, console

    ctx = get_context()

    valid_servers = {"blackfyre", "neo4j", "embedding", "all"}
    if server not in valid_servers:
        print_error(f"Unknown server: {server}. Choose from: {', '.join(valid_servers)}")
        raise typer.Exit(1)

    console.print(f"[bold]Starting MCP server: {server}[/bold]")
    console.print(f"[dim]Transport: {transport}, Port: {port}[/dim]\n")

    if server == "all":
        _serve_all(ctx, transport, port)
    elif server == "blackfyre":
        from revgraph.mcp.blackfyre_server import create_blackfyre_server

        srv = create_blackfyre_server()
        _run_server(srv, transport, port)
    elif server == "neo4j":
        from revgraph.mcp.neo4j_server import create_neo4j_server

        driver = ctx.ensure_neo4j()
        llm = ctx.ensure_llm()
        srv = create_neo4j_server(driver, llm)
        _run_server(srv, transport, port)
    elif server == "embedding":
        from revgraph.mcp.embedding_server import create_embedding_server

        driver = ctx.ensure_neo4j()
        llm = ctx.ensure_llm()
        srv = create_embedding_server(driver, llm)
        _run_server(srv, transport, port)


def _run_server(server, transport: str, port: int) -> None:
    if transport == "stdio":
        server.run(transport="stdio")
    else:
        server.run(transport="sse", port=port)


def _serve_all(ctx, transport: str, port: int) -> None:
    """Run all servers (composited into one for SSE, or sequential for stdio)."""
    from revgraph.mcp.neo4j_server import create_neo4j_server
    from revgraph.mcp.embedding_server import create_embedding_server
    from revgraph.mcp.blackfyre_server import create_blackfyre_server

    driver = ctx.ensure_neo4j()
    llm = ctx.ensure_llm()

    # For SSE, compose all tools into a single server
    from mcp.server.fastmcp import FastMCP

    combined = FastMCP("revgraph-all")

    for factory in [create_blackfyre_server, lambda: create_neo4j_server(driver, llm), lambda: create_embedding_server(driver, llm)]:
        srv = factory()
        for name, tool in srv._tools.items():
            combined._tools[name] = tool

    _run_server(combined, transport, port)
