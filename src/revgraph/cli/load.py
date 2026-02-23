"""revgraph load — load extracted artifacts into Neo4j."""

from __future__ import annotations

from pathlib import Path

import typer


def load_cmd(
    bcc_path: Path = typer.Argument(..., help="Path to .bcc file or directory"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Recursively scan directory"),
    batch_size: int = typer.Option(1000, "--batch-size", help="Batch size for UNWIND operations"),
    clear: bool = typer.Option(False, "--clear", help="Clear existing graph data before loading"),
    merge: bool = typer.Option(True, "--merge/--no-merge", help="Merge with existing data"),
) -> None:
    """Load BCC artifacts into the Neo4j graph database."""
    from revgraph.cli.app import get_context
    from revgraph.extraction.bcc_loader import load_bcc_file, load_bcc_directory
    from revgraph.graph.loader import GraphLoader
    from revgraph.utils.formatters import print_success, print_error

    ctx = get_context()

    if not bcc_path.exists():
        print_error(f"Path not found: {bcc_path}")
        raise typer.Exit(1)

    if bcc_path.is_dir():
        artifacts = load_bcc_directory(bcc_path, recursive=recursive)
    else:
        artifact = load_bcc_file(bcc_path)
        artifacts = [artifact] if artifact else []

    if not artifacts:
        print_error("No artifacts to load.")
        raise typer.Exit(1)

    driver = ctx.ensure_neo4j()
    loader = GraphLoader(driver)

    if clear:
        loader.clear_all()
        print_success("Cleared existing graph data")

    total_funcs = 0
    for art in artifacts:
        stats = loader.load_binary(art, batch_size=batch_size, merge=merge)
        total_funcs += stats.get("functions", 0)
        typer.echo(f"  Loaded {art.name}: {stats}")

    print_success(f"Loaded {len(artifacts)} binary(ies), {total_funcs} total functions")
