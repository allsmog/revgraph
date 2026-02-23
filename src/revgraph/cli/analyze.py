"""revgraph analyze — analysis subcommands (bbr, cluster, similarity)."""

from __future__ import annotations

from typing import Optional

import typer

analyze_app = typer.Typer(no_args_is_help=True)


@analyze_app.command()
def bbr(
    sha256: str = typer.Argument(..., help="Binary SHA256 to analyze"),
    iterations: int = typer.Option(20, "--iterations", help="PageRank iterations"),
    damping: float = typer.Option(0.85, "--damping", help="Damping factor"),
    write_to_graph: bool = typer.Option(False, "--write-to-graph", help="Store BBR scores in Neo4j"),
) -> None:
    """Compute Basic Block Rank (PageRank on CFG)."""
    from revgraph.cli.app import get_context
    from revgraph.analysis.bbr import compute_bbr
    from revgraph.utils.formatters import print_table, print_success

    ctx = get_context()
    driver = ctx.ensure_neo4j()

    scores = compute_bbr(driver, sha256, iterations=iterations, damping_factor=damping)

    if write_to_graph:
        from revgraph.analysis.bbr import write_bbr_scores

        write_bbr_scores(driver, sha256, scores)
        print_success(f"Wrote {len(scores)} BBR scores to graph")

    top = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:20]
    rows = [{"address": hex(addr), "bbr_score": f"{score:.6f}"} for addr, score in top]
    print_table(rows, title=f"Top BBR Scores — {sha256[:12]}...")


@analyze_app.command()
def cluster(
    method: str = typer.Option("hdbscan", "--method", help="Clustering method: hdbscan|kmeans"),
    n_clusters: int = typer.Option(10, "--n-clusters", "-k", help="Number of clusters (kmeans)"),
    export: Optional[str] = typer.Option(None, "--export", help="Export results to file"),
) -> None:
    """Cluster functions by embedding similarity."""
    from revgraph.cli.app import get_context
    from revgraph.analysis.clustering import cluster_functions
    from revgraph.utils.formatters import print_table, print_success

    ctx = get_context()
    driver = ctx.ensure_neo4j()

    results = cluster_functions(driver, method=method, n_clusters=n_clusters)
    print_success(f"Found {results['n_clusters']} clusters across {results['n_functions']} functions")

    if export:
        import json
        from pathlib import Path

        Path(export).write_text(json.dumps(results, default=str, indent=2))
        print_success(f"Exported to {export}")

    rows = [
        {"cluster": c["id"], "size": c["size"], "representative": c.get("representative", "N/A")}
        for c in results.get("clusters", [])[:20]
    ]
    print_table(rows, title="Clusters")


@analyze_app.command()
def similarity(
    function: str = typer.Argument(..., help="Function address or name"),
    cross_binary: bool = typer.Option(False, "--cross-binary", help="Search across all binaries"),
    top_k: int = typer.Option(10, "--top-k", help="Number of similar functions to return"),
) -> None:
    """Find similar functions by embedding distance."""
    from revgraph.cli.app import get_context
    from revgraph.embeddings.similarity import find_similar
    from revgraph.utils.formatters import print_table

    ctx = get_context()
    driver = ctx.ensure_neo4j()

    results = find_similar(driver, function, cross_binary=cross_binary, top_k=top_k)
    rows = [
        {
            "function": r["name"],
            "address": r.get("address", ""),
            "binary": r.get("binary", "")[:12] + "..." if r.get("binary") else "",
            "similarity": f"{r['score']:.4f}",
        }
        for r in results
    ]
    print_table(rows, title=f"Functions similar to {function}")
