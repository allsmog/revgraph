"""Tool functions for agent workflows."""

from __future__ import annotations

from typing import Any

from neo4j import Driver

from revgraph.llm.client import LLMClient


def _parse_address(address: str) -> int:
    """Parse an address string (hex or decimal) to int.

    LLMs produce addresses as strings — this handles ``"0x401000"``,
    ``"4198400"``, and ``"401000"`` (assumed hex if it contains a-f).
    """
    address = address.strip()
    if address.startswith("0x") or address.startswith("0X"):
        return int(address, 16)
    try:
        return int(address)
    except ValueError:
        # Contains hex digits like "401abc" — try hex
        return int(address, 16)


# ---------------------------------------------------------------------------
# Existing high-level tools
# ---------------------------------------------------------------------------

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
    from revgraph.analysis.bbr import compute_bbr as _compute
    from revgraph.analysis.bbr import write_bbr_scores

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
    driver: Driver, address: str | int, sha256: str
) -> list[dict[str, Any]]:
    """Get functions called by the given function."""
    addr = _parse_address(str(address)) if isinstance(address, str) else address
    with driver.session() as session:
        result = session.run(
            "MATCH (f:Function {address: $addr, binary_sha256: $sha256})"
            "-[:CALLS]->(callee:Function) "
            "RETURN callee.name AS name, callee.address AS address",
            addr=addr,
            sha256=sha256,
        )
        return [dict(r) for r in result]


def get_function_callers(
    driver: Driver, address: str | int, sha256: str
) -> list[dict[str, Any]]:
    """Get functions that call the given function."""
    addr = _parse_address(str(address)) if isinstance(address, str) else address
    with driver.session() as session:
        result = session.run(
            "MATCH (caller:Function)-[:CALLS]->"
            "(f:Function {address: $addr, binary_sha256: $sha256}) "
            "RETURN caller.name AS name, caller.address AS address",
            addr=addr,
            sha256=sha256,
        )
        return [dict(r) for r in result]


# ---------------------------------------------------------------------------
# Granular graph-navigation tools (for agentic tool-use pattern)
# ---------------------------------------------------------------------------

def get_function_details(
    driver: Driver, address: str, sha256: str
) -> dict[str, Any]:
    """Get decompiled code and metadata for a single function."""
    addr = _parse_address(address)
    with driver.session() as session:
        result = session.run(
            "MATCH (f:Function {address: $addr, binary_sha256: $sha256}) "
            "RETURN f.name AS name, f.address AS address, "
            "f.decompiled_code AS decompiled_code, "
            "f.summary AS summary, f.label AS label, "
            "f.binary_sha256 AS binary_sha256",
            addr=addr,
            sha256=sha256,
        )
        record = result.single()
        if not record:
            return {"error": f"Function at {address} not found in {sha256[:12]}"}
        return dict(record)


def get_function_strings(
    driver: Driver, address: str, sha256: str
) -> list[str]:
    """Get strings referenced by a single function."""
    addr = _parse_address(address)
    with driver.session() as session:
        result = session.run(
            "MATCH (f:Function {address: $addr, binary_sha256: $sha256})"
            "-[:REFERENCES_STRING]->(s:String) "
            "RETURN DISTINCT s.value AS value",
            addr=addr,
            sha256=sha256,
        )
        return [r["value"] for r in result]


def get_function_imports(
    driver: Driver, address: str, sha256: str
) -> list[str]:
    """Get imports referenced by a single function."""
    addr = _parse_address(address)
    with driver.session() as session:
        result = session.run(
            "MATCH (f:Function {address: $addr, binary_sha256: $sha256})"
            "-[:REFERENCES_IMPORT]->(i:Import) "
            "RETURN DISTINCT i.name AS name",
            addr=addr,
            sha256=sha256,
        )
        return [r["name"] for r in result]


def list_functions(
    driver: Driver, sha256: str, offset: int = 0, limit: int = 20
) -> list[dict[str, Any]]:
    """List functions in a binary with pagination."""
    with driver.session() as session:
        result = session.run(
            "MATCH (f:Function {binary_sha256: $sha256}) "
            "RETURN f.name AS name, f.address AS address, "
            "f.summary AS summary, f.label AS label "
            "ORDER BY f.address "
            "SKIP $offset LIMIT $limit",
            sha256=sha256,
            offset=offset,
            limit=limit,
        )
        return [dict(r) for r in result]


def get_basic_blocks(
    driver: Driver, address: str, sha256: str
) -> list[dict[str, Any]]:
    """Get basic blocks (CFG) for a single function."""
    addr = _parse_address(address)
    with driver.session() as session:
        result = session.run(
            "MATCH (f:Function {address: $addr, binary_sha256: $sha256})"
            "-[:CONTAINS]->(bb:BasicBlock) "
            "OPTIONAL MATCH (bb)-[:FLOWS_TO]->(succ:BasicBlock) "
            "RETURN bb.address AS address, bb.size AS size, "
            "bb.bbr_score AS bbr_score, "
            "collect(DISTINCT succ.address) AS successors "
            "ORDER BY bb.address",
            addr=addr,
            sha256=sha256,
        )
        return [dict(r) for r in result]


def get_instructions(
    driver: Driver, block_address: str, sha256: str
) -> list[dict[str, Any]]:
    """Get instructions within a single basic block."""
    addr = _parse_address(block_address)
    with driver.session() as session:
        result = session.run(
            "MATCH (bb:BasicBlock {address: $addr, binary_sha256: $sha256})"
            "-[:CONTAINS]->(i:Instruction) "
            "RETURN i.address AS address, i.mnemonic AS mnemonic, "
            "i.operands AS operands, i.bytes AS bytes "
            "ORDER BY i.address",
            addr=addr,
            sha256=sha256,
        )
        return [dict(r) for r in result]


def search_strings(
    driver: Driver, query: str, sha256: str, limit: int = 20
) -> list[dict[str, Any]]:
    """Search strings in a binary by substring match."""
    with driver.session() as session:
        result = session.run(
            "MATCH (s:String {binary_sha256: $sha256}) "
            "WHERE toLower(s.value) CONTAINS toLower($query) "
            "RETURN s.value AS value, s.address AS address "
            "LIMIT $limit",
            query=query,
            sha256=sha256,
            limit=limit,
        )
        return [dict(r) for r in result]


def search_functions(
    driver: Driver, query: str, sha256: str, limit: int = 20
) -> list[dict[str, Any]]:
    """Search functions by name pattern in a binary."""
    with driver.session() as session:
        result = session.run(
            "MATCH (f:Function {binary_sha256: $sha256}) "
            "WHERE toLower(f.name) CONTAINS toLower($query) "
            "RETURN f.name AS name, f.address AS address, "
            "f.summary AS summary "
            "LIMIT $limit",
            query=query,
            sha256=sha256,
            limit=limit,
        )
        return [dict(r) for r in result]
