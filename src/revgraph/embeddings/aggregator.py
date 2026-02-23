"""BBR-weighted embedding aggregation."""

from __future__ import annotations

import numpy as np

from revgraph.utils.logging import get_logger

log = get_logger(__name__)


def aggregate_block_embeddings(
    block_embeddings: list[list[float]],
    bbr_scores: list[float] | None = None,
) -> list[float]:
    """Aggregate block-level embeddings into a function-level embedding.

    If BBR scores are provided, use them as weights.
    Otherwise, use simple mean aggregation.
    """
    if not block_embeddings:
        return []

    X = np.array(block_embeddings)

    if bbr_scores is not None and len(bbr_scores) == len(block_embeddings):
        weights = np.array(bbr_scores, dtype=np.float64)
        # Normalize weights
        total = weights.sum()
        if total > 0:
            weights /= total
        else:
            weights = np.ones(len(block_embeddings)) / len(block_embeddings)

        aggregated = (X.T @ weights).tolist()
    else:
        aggregated = X.mean(axis=0).tolist()

    # L2 normalize
    norm = np.linalg.norm(aggregated)
    if norm > 0:
        aggregated = (np.array(aggregated) / norm).tolist()

    return aggregated


def aggregate_function_embeddings(
    function_embeddings: list[list[float]],
    function_bbr_scores: list[float] | None = None,
) -> list[float]:
    """Aggregate function-level embeddings into a binary-level embedding."""
    return aggregate_block_embeddings(function_embeddings, function_bbr_scores)
