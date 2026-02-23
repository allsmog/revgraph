"""Cosine similarity and nearest-neighbor search on embeddings."""

from __future__ import annotations

from typing import Any

import numpy as np
from neo4j import Driver

from revgraph.utils.logging import get_logger

log = get_logger(__name__)


def find_similar(
    driver: Driver,
    function: str,
    cross_binary: bool = False,
    top_k: int = 10,
) -> list[dict[str, Any]]:
    """Find functions most similar to the given function by embedding distance.

    `function` can be a function name or hex address string.
    """
    # Resolve the target embedding
    target_vec, target_sha256 = _resolve_embedding(driver, function)
    if target_vec is None:
        log.warning("no_embedding_found", function=function)
        return []

    # Try Neo4j vector index first (Neo4j 5.11+)
    try:
        return _vector_index_search(driver, target_vec, target_sha256, cross_binary, top_k)
    except Exception:
        log.debug("vector_index_unavailable, using brute-force search")

    # Fallback: brute-force cosine similarity
    return _brute_force_search(driver, target_vec, target_sha256, cross_binary, top_k)


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    a_arr = np.array(a, dtype=np.float64)
    b_arr = np.array(b, dtype=np.float64)
    dot = np.dot(a_arr, b_arr)
    norm_a = np.linalg.norm(a_arr)
    norm_b = np.linalg.norm(b_arr)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(dot / (norm_a * norm_b))


def pairwise_similarity_matrix(
    embeddings: list[list[float]],
) -> np.ndarray:
    """Compute pairwise cosine similarity matrix."""
    X = np.array(embeddings, dtype=np.float64)
    norms = np.linalg.norm(X, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    X_normed = X / norms
    return X_normed @ X_normed.T


def _resolve_embedding(
    driver: Driver, function: str
) -> tuple[list[float] | None, str | None]:
    """Resolve a function identifier to its embedding vector."""
    with driver.session() as session:
        # Try as hex address
        try:
            addr = int(function, 16) if function.startswith("0x") else int(function)
            result = session.run(
                "MATCH (f:Function {address: $addr})-[:HAS_EMBEDDING]->(e:Embedding) "
                "RETURN e.vector AS vector, f.binary_sha256 AS sha256 LIMIT 1",
                addr=addr,
            )
            record = result.single()
            if record:
                return list(record["vector"]), record["sha256"]
        except ValueError:
            pass

        # Try as function name
        result = session.run(
            "MATCH (f:Function {name: $name})-[:HAS_EMBEDDING]->(e:Embedding) "
            "RETURN e.vector AS vector, f.binary_sha256 AS sha256 LIMIT 1",
            name=function,
        )
        record = result.single()
        if record:
            return list(record["vector"]), record["sha256"]

    return None, None


def _vector_index_search(
    driver: Driver,
    target_vec: list[float],
    target_sha256: str | None,
    cross_binary: bool,
    top_k: int,
) -> list[dict[str, Any]]:
    """Use Neo4j vector index for similarity search."""
    with driver.session() as session:
        if cross_binary:
            result = session.run(
                "CALL db.index.vector.queryNodes('embedding_vector', $k, $vec) "
                "YIELD node, score "
                "MATCH (f:Function)-[:HAS_EMBEDDING]->(node) "
                "RETURN f.name AS name, f.address AS address, "
                "f.binary_sha256 AS binary, score "
                "ORDER BY score DESC",
                k=top_k + 1,
                vec=target_vec,
            )
        else:
            result = session.run(
                "CALL db.index.vector.queryNodes('embedding_vector', $k, $vec) "
                "YIELD node, score "
                "MATCH (f:Function)-[:HAS_EMBEDDING]->(node) "
                "WHERE f.binary_sha256 = $sha256 "
                "RETURN f.name AS name, f.address AS address, "
                "f.binary_sha256 AS binary, score "
                "ORDER BY score DESC",
                k=top_k + 1,
                vec=target_vec,
                sha256=target_sha256,
            )

        results = [dict(r) for r in result]
        # Remove self-match
        return [r for r in results if r.get("score", 1.0) < 0.9999][:top_k]


def _brute_force_search(
    driver: Driver,
    target_vec: list[float],
    target_sha256: str | None,
    cross_binary: bool,
    top_k: int,
) -> list[dict[str, Any]]:
    """Brute-force cosine similarity search."""
    with driver.session() as session:
        if cross_binary:
            query = (
                "MATCH (f:Function)-[:HAS_EMBEDDING]->(e:Embedding) "
                "RETURN f.name AS name, f.address AS address, "
                "f.binary_sha256 AS binary, e.vector AS vector"
            )
            result = session.run(query)
        else:
            query = (
                "MATCH (f:Function {binary_sha256: $sha256})-[:HAS_EMBEDDING]->(e:Embedding) "
                "RETURN f.name AS name, f.address AS address, "
                "f.binary_sha256 AS binary, e.vector AS vector"
            )
            result = session.run(query, sha256=target_sha256)

        candidates = []
        for record in result:
            vec = record["vector"]
            if vec is not None:
                score = cosine_similarity(target_vec, list(vec))
                if score < 0.9999:  # Exclude self
                    candidates.append(
                        {
                            "name": record["name"],
                            "address": record["address"],
                            "binary": record["binary"],
                            "score": score,
                        }
                    )

    candidates.sort(key=lambda x: x["score"], reverse=True)
    return candidates[:top_k]
