"""revgraph extract — parse BCC protobuf files into normalized artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer


def extract_cmd(
    bcc_path: Path = typer.Argument(..., help="Path to .bcc file or directory"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Recursively scan directory"),
    vex: bool = typer.Option(False, "--vex/--no-vex", help="Lift VEX IR for instructions"),
    load: bool = typer.Option(False, "--load", help="Immediately load into Neo4j after extraction"),
    batch_size: int = typer.Option(1000, "--batch-size", help="Batch size for graph loading"),
) -> None:
    """Extract binary artifacts from BCC protobuf files."""
    from revgraph.cli.app import get_context
    from revgraph.extraction.bcc_loader import load_bcc_file, load_bcc_directory
    from revgraph.utils.formatters import print_success, print_error

    ctx = get_context()

    if not bcc_path.exists():
        print_error(f"Path not found: {bcc_path}")
        raise typer.Exit(1)

    artifacts = []
    if bcc_path.is_dir():
        artifacts = load_bcc_directory(bcc_path, recursive=recursive, lift_vex=vex)
    else:
        artifact = load_bcc_file(bcc_path, lift_vex=vex)
        if artifact:
            artifacts = [artifact]

    if not artifacts:
        print_error("No artifacts extracted.")
        raise typer.Exit(1)

    print_success(f"Extracted {len(artifacts)} binary artifact(s)")

    for art in artifacts:
        typer.echo(
            f"  {art.name}: {len(art.functions)} functions, "
            f"{sum(len(f.basic_blocks) for f in art.functions)} blocks"
        )

    if load:
        from revgraph.graph.loader import GraphLoader

        driver = ctx.ensure_neo4j()
        loader = GraphLoader(driver)
        for art in artifacts:
            loader.load_binary(art, batch_size=batch_size)
        print_success("Loaded into Neo4j")
