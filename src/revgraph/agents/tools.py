"""Tool functions for agent workflows."""

from __future__ import annotations

from typing import Any

from neo4j import Driver

from revgraph.llm.client import LLMClient


def load_binary_info(driver: Driver, sha256: str) -> dict[str, Any]:
    """Load binary metadata from the graph."""
    with driver.session() as session:
        result = session.run(
            "MATCH (b:BinaryFile {sha256: $sha256}) "
            "OPTIONAL MATCH (b)-[:DEFINES]->(f:Function) "
            "RETURN b.name AS name, b.sha256 AS sha256, "
            "b.architecture AS architecture, b.file_type AS file_type, "
            "count(f) AS num_functions",
            sha256=sha256,
        )
        record = result.single()
        return dict(record) if record else {"error": f"Binary {sha256} not found"}


def query_graph(driver: Driver, cypher: str) -> list[dict[str, Any]]:
    """Execute a Cypher query and return results."""
    from revgraph.graph.query_engine import QueryEngine

    engine = QueryEngine(driver)
    return engine.execute(cypher, limit=100)


def nl_query(
    driver: Driver, llm: LLMClient, question: str
) -> dict[str, Any]:
    """Translate and execute a natural language query."""
    from revgraph.nl2gql.translator import NL2CypherTranslator

    translator = NL2CypherTranslator(llm, driver)
    cypher, results = translator.translate_and_execute(question)
    return {"cypher": cypher, "results": results}


def compute_bbr(driver: Driver, sha256: str) -> dict[str, Any]:
    """Compute BBR scores for a binary."""
    from revgraph.analysis.bbr import compute_bbr as _compute, write_bbr_scores

    scores = _compute(driver, sha256)
    write_bbr_scores(driver, sha256, scores)
    top = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:10]
    return {
        "total_blocks": len(scores),
        "top_blocks": [{"address": hex(a), "score": s} for a, s in top],
    }


def find_similar_functions(
    driver: Driver, function: str, top_k: int = 10
) -> list[dict[str, Any]]:
    """Find similar functions by embedding distance."""
    from revgraph.embeddings.similarity import find_similar

    return find_similar(driver, function, cross_binary=True, top_k=top_k)


def get_dangerous_functions(
    driver: Driver, sha256: str
) -> list[dict[str, Any]]:
    """Find functions using dangerous APIs."""
    from revgraph.analysis.vulnerability import find_dangerous_functions

    return find_dangerous_functions(driver, sha256)


def summarize_function(
    driver: Driver, llm: LLMClient, target: str
) -> str:
    """Summarize a function using LLM."""
    from revgraph.llm.summarizer import Summarizer

    summarizer = Summarizer(llm, driver)
    result = summarizer.summarize(target, scope="function")
    return result.get("summary", "")


def generate_yara_rule(
    driver: Driver, llm: LLMClient, sha256: str
) -> str:
    """Generate YARA rules for a binary."""
    from revgraph.llm.yara_generator import YARAGenerator

    generator = YARAGenerator(llm, driver)
    return generator.generate(sha256)


def get_function_callees(
    driver: Driver, address: int, sha256: str
) -> list[dict[str, Any]]:
    """Get functions called by the given function."""
    with driver.session() as session:
        result = session.run(
            "MATCH (f:Function {address: $addr, binary_sha256: $sha256})"
            "-[:CALLS]->(callee:Function) "
            "RETURN callee.name AS name, callee.address AS address",
            addr=address,
            sha256=sha256,
        )
        return [dict(r) for r in result]


def get_function_callers(
    driver: Driver, address: int, sha256: str
) -> list[dict[str, Any]]:
    """Get functions that call the given function."""
    with driver.session() as session:
        result = session.run(
            "MATCH (caller:Function)-[:CALLS]->"
            "(f:Function {address: $addr, binary_sha256: $sha256}) "
            "RETURN caller.name AS name, caller.address AS address",
            addr=address,
            sha256=sha256,
        )
        return [dict(r) for r in result]
