"""Higher-level embedding tasks: function naming, binary similarity, retrieval."""

from __future__ import annotations

from typing import Any

from neo4j import Driver

from revgraph.embeddings.similarity import cosine_similarity, find_similar
from revgraph.utils.logging import get_logger

log = get_logger(__name__)


def suggest_function_names(
    driver: Driver, sha256: str, top_k: int = 5
) -> list[dict[str, Any]]:
    """Suggest names for unnamed functions based on similar named functions.

    Finds functions with generic names (FUN_, sub_, etc.) and looks for
    similar functions that have meaningful names.
    """
    with driver.session() as session:
        # Find functions with generic names
        result = session.run(
            "MATCH (f:Function {binary_sha256: $sha256}) "
            "WHERE f.name STARTS WITH 'FUN_' OR f.name STARTS WITH 'sub_' "
            "OR f.name STARTS WITH 'fcn.' "
            "RETURN f.name AS name, f.address AS address",
            sha256=sha256,
        )
        unnamed = [dict(r) for r in result]

    suggestions = []
    for func in unnamed:
        similar = find_similar(driver, str(func["address"]), cross_binary=True, top_k=top_k)
        # Filter to those with meaningful names
        named_similar = [
            s for s in similar
            if not any(s["name"].startswith(p) for p in ("FUN_", "sub_", "fcn."))
        ]
        if named_similar:
            suggestions.append(
                {
                    "address": func["address"],
                    "current_name": func["name"],
                    "suggested_names": [
                        {"name": s["name"], "similarity": s["score"]}
                        for s in named_similar[:3]
                    ],
                }
            )

    return suggestions


def binary_similarity_score(
    driver: Driver, sha256_a: str, sha256_b: str
) -> float:
    """Compute overall similarity between two binaries based on function embeddings."""
    emb_a = _get_binary_embeddings(driver, sha256_a)
    emb_b = _get_binary_embeddings(driver, sha256_b)

    if not emb_a or not emb_b:
        return 0.0

    # Average best-match similarity
    scores = []
    for vec_a in emb_a:
        best = max(cosine_similarity(vec_a, vec_b) for vec_b in emb_b)
        scores.append(best)

    return sum(scores) / len(scores) if scores else 0.0


def retrieve_similar_code(
    driver: Driver, query_text: str, llm_client, top_k: int = 5
) -> list[dict[str, Any]]:
    """Embed a text query and find similar functions (RAG-style retrieval)."""
    query_vec = llm_client.embed([query_text])[0]

    with driver.session() as session:
        try:
            result = session.run(
                "CALL db.index.vector.queryNodes('embedding_vector', $k, $vec) "
                "YIELD node, score "
                "MATCH (f:Function)-[:HAS_EMBEDDING]->(node) "
                "RETURN f.name AS name, f.address AS address, "
                "f.binary_sha256 AS binary, f.decompiled_code AS code, score "
                "ORDER BY score DESC",
                k=top_k,
                vec=query_vec,
            )
            return [dict(r) for r in result]
        except Exception:
            log.debug("vector_search_failed, trying brute force")
            return []


def _get_binary_embeddings(
    driver: Driver, sha256: str
) -> list[list[float]]:
    """Get all function embeddings for a binary."""
    with driver.session() as session:
        result = session.run(
            "MATCH (f:Function {binary_sha256: $sha256})-[:HAS_EMBEDDING]->(e:Embedding) "
            "RETURN e.vector AS vector",
            sha256=sha256,
        )
        return [list(r["vector"]) for r in result if r["vector"] is not None]
