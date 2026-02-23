"""Integration tests for graph loading (requires Neo4j)."""

import pytest


@pytest.mark.integration
def test_load_and_query_binary(neo4j_driver, sample_artifact):
    """Test loading a binary artifact and querying it."""
    from revgraph.graph.schema import create_schema
    from revgraph.graph.loader import GraphLoader
    from revgraph.graph.query_engine import QueryEngine

    create_schema(neo4j_driver)
    loader = GraphLoader(neo4j_driver)

    stats = loader.load_binary(sample_artifact)
    assert stats["functions"] == 2
    assert stats["calls"] >= 1

    engine = QueryEngine(neo4j_driver)
    results = engine.execute(
        "MATCH (b:BinaryFile) RETURN b.name AS name, b.sha256 AS sha256"
    )
    assert len(results) == 1
    assert results[0]["name"] == "test_binary"

    # Query functions
    funcs = engine.execute(
        "MATCH (f:Function {binary_sha256: $sha256}) RETURN f.name AS name ORDER BY f.name",
        params={"sha256": "a" * 64},
    )
    assert len(funcs) == 2
    assert funcs[0]["name"] == "helper"
    assert funcs[1]["name"] == "main"


@pytest.mark.integration
def test_clear_graph(neo4j_driver, sample_artifact):
    """Test clearing the graph."""
    from revgraph.graph.loader import GraphLoader
    from revgraph.graph.query_engine import QueryEngine

    loader = GraphLoader(neo4j_driver)
    loader.load_binary(sample_artifact)

    engine = QueryEngine(neo4j_driver)
    results = engine.execute("MATCH (n) RETURN count(n) AS cnt")
    assert results[0]["cnt"] > 0

    loader.clear_all()
    results = engine.execute("MATCH (n) RETURN count(n) AS cnt")
    assert results[0]["cnt"] == 0
