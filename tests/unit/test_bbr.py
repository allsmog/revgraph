"""Tests for Basic Block Rank computation."""

from unittest.mock import MagicMock, patch

import numpy as np

from revgraph.analysis.bbr import compute_bbr


def test_compute_bbr_empty():
    """BBR returns empty dict when no blocks exist."""
    driver = MagicMock()
    session = MagicMock()
    driver.session.return_value.__enter__ = MagicMock(return_value=session)
    driver.session.return_value.__exit__ = MagicMock(return_value=False)

    # No blocks
    session.run.return_value = iter([])

    scores = compute_bbr(driver, "a" * 64)
    assert scores == {}


def test_compute_bbr_simple_chain():
    """BBR on a simple A->B->C chain."""
    driver = MagicMock()
    session = MagicMock()
    driver.session.return_value.__enter__ = MagicMock(return_value=session)
    driver.session.return_value.__exit__ = MagicMock(return_value=False)

    # Mock blocks query then edges query
    blocks = [{"address": 1}, {"address": 2}, {"address": 3}]
    edges = [{"source": 1, "target": 2}, {"source": 2, "target": 3}]

    call_count = 0

    def mock_run(query, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return iter(blocks)
        return iter(edges)

    session.run = mock_run

    scores = compute_bbr(driver, "a" * 64)
    assert len(scores) == 3
    # Scores should sum to ~1.0
    assert abs(sum(scores.values()) - 1.0) < 0.001
    # In a chain, the last node should have highest score (sink)
    assert scores[3] > scores[1]


def test_compute_bbr_convergence():
    """BBR scores sum to 1.0 after convergence."""
    driver = MagicMock()
    session = MagicMock()
    driver.session.return_value.__enter__ = MagicMock(return_value=session)
    driver.session.return_value.__exit__ = MagicMock(return_value=False)

    # Cycle: A->B->C->A
    blocks = [{"address": 1}, {"address": 2}, {"address": 3}]
    edges = [
        {"source": 1, "target": 2},
        {"source": 2, "target": 3},
        {"source": 3, "target": 1},
    ]

    call_count = 0

    def mock_run(query, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return iter(blocks)
        return iter(edges)

    session.run = mock_run

    scores = compute_bbr(driver, "a" * 64)
    assert abs(sum(scores.values()) - 1.0) < 0.001
    # In a cycle, all nodes should have equal score
    values = list(scores.values())
    assert all(abs(v - values[0]) < 0.01 for v in values)
