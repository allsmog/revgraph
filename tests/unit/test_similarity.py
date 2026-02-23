"""Tests for embedding similarity functions."""

import numpy as np

from revgraph.embeddings.similarity import cosine_similarity, pairwise_similarity_matrix
from revgraph.embeddings.aggregator import aggregate_block_embeddings


def test_cosine_similarity_identical():
    vec = [1.0, 2.0, 3.0]
    assert abs(cosine_similarity(vec, vec) - 1.0) < 1e-6


def test_cosine_similarity_orthogonal():
    a = [1.0, 0.0, 0.0]
    b = [0.0, 1.0, 0.0]
    assert abs(cosine_similarity(a, b)) < 1e-6


def test_cosine_similarity_opposite():
    a = [1.0, 0.0]
    b = [-1.0, 0.0]
    assert abs(cosine_similarity(a, b) - (-1.0)) < 1e-6


def test_cosine_similarity_zero_vector():
    a = [0.0, 0.0, 0.0]
    b = [1.0, 2.0, 3.0]
    assert cosine_similarity(a, b) == 0.0


def test_pairwise_similarity_matrix():
    embeddings = [[1.0, 0.0], [0.0, 1.0], [1.0, 1.0]]
    matrix = pairwise_similarity_matrix(embeddings)
    assert matrix.shape == (3, 3)
    # Diagonal should be 1.0
    for i in range(3):
        assert abs(matrix[i][i] - 1.0) < 1e-6
    # [1,0] and [0,1] should be orthogonal
    assert abs(matrix[0][1]) < 1e-6


def test_aggregate_block_embeddings_mean():
    blocks = [[1.0, 0.0], [0.0, 1.0]]
    result = aggregate_block_embeddings(blocks)
    assert len(result) == 2
    # L2 normalized mean of [0.5, 0.5]
    expected_norm = np.sqrt(0.5)
    assert abs(result[0] - expected_norm) < 1e-6
    assert abs(result[1] - expected_norm) < 1e-6


def test_aggregate_block_embeddings_weighted():
    blocks = [[1.0, 0.0], [0.0, 1.0]]
    weights = [0.9, 0.1]
    result = aggregate_block_embeddings(blocks, bbr_scores=weights)
    assert len(result) == 2
    # Should be heavily weighted toward first block
    assert result[0] > result[1]


def test_aggregate_empty():
    assert aggregate_block_embeddings([]) == []
