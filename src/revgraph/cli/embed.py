"""revgraph embed — generate and store embeddings."""

from __future__ import annotations

from typing import Optional

import typer


def embed_cmd(
    target: str = typer.Argument("all", help="Binary SHA256 or 'all'"),
    model: Optional[str] = typer.Option(None, "--model", help="Embedding model override"),
    scope: str = typer.Option("functions", "--scope", help="functions|blocks"),
    bbr_weighted: bool = typer.Option(False, "--bbr-weighted", help="Weight by BBR scores"),
    write_to_graph: bool = typer.Option(False, "--write-to-graph", help="Store embeddings in Neo4j"),
) -> None:
    """Generate embeddings for binary artifacts."""
    from revgraph.cli.app import get_context
    from revgraph.embeddings.generator import EmbeddingGenerator
    from revgraph.embeddings.store import EmbeddingStore
    from revgraph.utils.formatters import print_success, print_error

    ctx = get_context()
    cfg = ctx.ensure_config()
    driver = ctx.ensure_neo4j()
    llm = ctx.ensure_llm()

    embedding_model = model or cfg.embeddings.default_model
    generator = EmbeddingGenerator(llm, model=embedding_model)

    from revgraph.graph.query_engine import QueryEngine

    engine = QueryEngine(driver)

    if target == "all":
        binaries = engine.execute("MATCH (b:BinaryFile) RETURN b.sha256 AS sha256")
        sha256_list = [r["sha256"] for r in binaries]
    else:
        sha256_list = [target]

    if not sha256_list:
        print_error("No binaries found in graph")
        raise typer.Exit(1)

    store = EmbeddingStore(driver)
    total = 0

    for sha256 in sha256_list:
        embeddings = generator.generate_for_binary(
            driver, sha256, scope=scope, bbr_weighted=bbr_weighted
        )
        total += len(embeddings)
        if write_to_graph:
            store.write_embeddings(embeddings, sha256)
        typer.echo(f"  {sha256[:12]}...: {len(embeddings)} embeddings")

    msg = f"Generated {total} embeddings"
    if write_to_graph:
        msg += " (written to graph)"
    print_success(msg)
