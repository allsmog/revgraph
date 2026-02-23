"""Function clustering by embedding similarity."""

from __future__ import annotations

from typing import Any

import numpy as np
from neo4j import Driver
from sklearn.cluster import KMeans

from revgraph.utils.logging import get_logger

log = get_logger(__name__)


def cluster_functions(
    driver: Driver,
    method: str = "hdbscan",
    n_clusters: int = 10,
    min_cluster_size: int = 5,
) -> dict[str, Any]:
    """Cluster functions based on their embeddings."""
    # 1. Fetch embeddings from graph
    embeddings, func_info = _fetch_embeddings(driver)
    if len(embeddings) < 2:
        return {"n_clusters": 0, "n_functions": len(embeddings), "clusters": []}

    X = np.array(embeddings)

    # 2. Cluster
    if method == "hdbscan":
        labels = _cluster_hdbscan(X, min_cluster_size)
    elif method == "kmeans":
        labels = _cluster_kmeans(X, n_clusters)
    else:
        raise ValueError(f"Unknown clustering method: {method}")

    # 3. Build results
    unique_labels = set(labels)
    unique_labels.discard(-1)  # Remove noise label for HDBSCAN

    clusters = []
    for label_id in sorted(unique_labels):
        members = [func_info[i] for i, l in enumerate(labels) if l == label_id]
        # Find representative (closest to centroid)
        member_indices = [i for i, l in enumerate(labels) if l == label_id]
        centroid = X[member_indices].mean(axis=0)
        dists = np.linalg.norm(X[member_indices] - centroid, axis=1)
        rep_idx = member_indices[int(np.argmin(dists))]

        clusters.append(
            {
                "id": int(label_id),
                "size": len(members),
                "representative": func_info[rep_idx].get("name", "unknown"),
                "members": members,
            }
        )

    noise_count = sum(1 for l in labels if l == -1)

    return {
        "n_clusters": len(clusters),
        "n_functions": len(embeddings),
        "noise": noise_count,
        "method": method,
        "clusters": clusters,
    }


def _cluster_hdbscan(X: np.ndarray, min_cluster_size: int) -> list[int]:
    """Cluster using HDBSCAN (falls back to KMeans if unavailable)."""
    try:
        from sklearn.cluster import HDBSCAN

        clusterer = HDBSCAN(min_cluster_size=min_cluster_size)
        return list(clusterer.fit_predict(X))
    except ImportError:
        log.warning("hdbscan_unavailable, falling back to KMeans")
        return _cluster_kmeans(X, n_clusters=10)


def _cluster_kmeans(X: np.ndarray, n_clusters: int) -> list[int]:
    """Cluster using KMeans."""
    actual_k = min(n_clusters, len(X))
    km = KMeans(n_clusters=actual_k, random_state=42, n_init=10)
    return list(km.fit_predict(X))


def _fetch_embeddings(
    driver: Driver,
) -> tuple[list[list[float]], list[dict[str, Any]]]:
    """Fetch function embeddings from Neo4j."""
    embeddings: list[list[float]] = []
    func_info: list[dict[str, Any]] = []

    with driver.session() as session:
        result = session.run(
            "MATCH (f:Function)-[:HAS_EMBEDDING]->(e:Embedding) "
            "RETURN f.name AS name, f.address AS address, "
            "f.binary_sha256 AS binary, e.vector AS vector"
        )
        for record in result:
            vec = record["vector"]
            if vec is not None:
                embeddings.append(list(vec))
                func_info.append(
                    {
                        "name": record["name"],
                        "address": record["address"],
                        "binary": record["binary"],
                    }
                )

    log.info("fetched_embeddings", count=len(embeddings))
    return embeddings, func_info
