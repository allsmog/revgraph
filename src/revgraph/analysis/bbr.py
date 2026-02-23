"""Basic Block Rank — PageRank on the Control Flow Graph."""

from __future__ import annotations

from typing import Any

import numpy as np
from neo4j import Driver

from revgraph.utils.logging import get_logger

log = get_logger(__name__)


def compute_bbr(
    driver: Driver,
    sha256: str,
    iterations: int = 20,
    damping_factor: float = 0.85,
) -> dict[int, float]:
    """Compute PageRank scores for all basic blocks in a binary.

    Returns mapping of block_address -> bbr_score.
    """
    # 1. Extract CFG edges from the graph
    edges, nodes = _extract_cfg(driver, sha256)
    if not nodes:
        log.warning("no_basic_blocks", sha256=sha256[:12])
        return {}

    # 2. Build adjacency matrix
    node_list = sorted(nodes)
    idx = {addr: i for i, addr in enumerate(node_list)}
    n = len(node_list)

    # Out-link matrix (column-stochastic for PageRank)
    out_degree = np.zeros(n, dtype=np.float64)
    M = np.zeros((n, n), dtype=np.float64)

    for src, tgt in edges:
        if src in idx and tgt in idx:
            i_src = idx[src]
            i_tgt = idx[tgt]
            M[i_tgt][i_src] = 1.0
            out_degree[i_src] += 1.0

    # Normalize columns
    for j in range(n):
        if out_degree[j] > 0:
            M[:, j] /= out_degree[j]
        else:
            # Dangling node: distribute equally
            M[:, j] = 1.0 / n

    # 3. Power iteration
    rank = np.ones(n, dtype=np.float64) / n
    teleport = np.ones(n, dtype=np.float64) / n

    for _ in range(iterations):
        rank = damping_factor * M @ rank + (1 - damping_factor) * teleport

    # Normalize to sum to 1
    rank_sum = rank.sum()
    if rank_sum > 0:
        rank /= rank_sum

    scores = {node_list[i]: float(rank[i]) for i in range(n)}
    log.info("bbr_computed", sha256=sha256[:12], blocks=n, iterations=iterations)
    return scores


def write_bbr_scores(
    driver: Driver, sha256: str, scores: dict[int, float]
) -> None:
    """Write BBR scores back to BasicBlock nodes in Neo4j."""
    rows = [{"address": addr, "score": score} for addr, score in scores.items()]
    batch_size = 500

    with driver.session() as session:
        for i in range(0, len(rows), batch_size):
            batch = rows[i : i + batch_size]
            session.run(
                "UNWIND $rows AS r "
                "MATCH (bb:BasicBlock {address: r.address, binary_sha256: $sha256}) "
                "SET bb.bbr_score = r.score",
                rows=batch,
                sha256=sha256,
            )

    log.info("bbr_scores_written", sha256=sha256[:12], count=len(rows))


def get_top_bbr_blocks(
    driver: Driver, sha256: str, limit: int = 20
) -> list[dict[str, Any]]:
    """Retrieve top BBR-scored basic blocks."""
    with driver.session() as session:
        result = session.run(
            "MATCH (bb:BasicBlock {binary_sha256: $sha256}) "
            "WHERE bb.bbr_score IS NOT NULL "
            "RETURN bb.address AS address, bb.bbr_score AS bbr_score "
            "ORDER BY bb.bbr_score DESC LIMIT $limit",
            sha256=sha256,
            limit=limit,
        )
        return [dict(r) for r in result]


def get_top_bbr_functions(
    driver: Driver, sha256: str, limit: int = 20
) -> list[dict[str, Any]]:
    """Retrieve functions ranked by average BBR score of their blocks."""
    with driver.session() as session:
        result = session.run(
            "MATCH (f:Function {binary_sha256: $sha256})-[:CONTAINS]->(bb:BasicBlock) "
            "WHERE bb.bbr_score IS NOT NULL "
            "WITH f, avg(bb.bbr_score) AS avg_bbr, max(bb.bbr_score) AS max_bbr, "
            "count(bb) AS block_count "
            "RETURN f.name AS name, f.address AS address, avg_bbr, max_bbr, block_count "
            "ORDER BY max_bbr DESC LIMIT $limit",
            sha256=sha256,
            limit=limit,
        )
        return [dict(r) for r in result]


def _extract_cfg(
    driver: Driver, sha256: str
) -> tuple[list[tuple[int, int]], set[int]]:
    """Extract CFG edges and node set from Neo4j."""
    edges: list[tuple[int, int]] = []
    nodes: set[int] = set()

    with driver.session() as session:
        # Get all blocks
        result = session.run(
            "MATCH (bb:BasicBlock {binary_sha256: $sha256}) "
            "RETURN bb.address AS address",
            sha256=sha256,
        )
        for record in result:
            nodes.add(record["address"])

        # Get all flow edges
        result = session.run(
            "MATCH (src:BasicBlock {binary_sha256: $sha256})-[:FLOW_TO]->(tgt:BasicBlock) "
            "RETURN src.address AS source, tgt.address AS target",
            sha256=sha256,
        )
        for record in result:
            edges.append((record["source"], record["target"]))

    return edges, nodes
