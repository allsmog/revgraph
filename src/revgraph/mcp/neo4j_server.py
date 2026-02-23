"""MCP server for Neo4j graph queries."""

from __future__ import annotations

from neo4j import Driver

from mcp.server.fastmcp import FastMCP

from revgraph.llm.client import LLMClient


def create_neo4j_server(driver: Driver, llm: LLMClient) -> FastMCP:
    mcp = FastMCP("revgraph-neo4j")

    @mcp.tool()
    def query_graph(cypher: str) -> list[dict]:
        """Execute a Cypher query against the Neo4j graph database."""
        from revgraph.graph.query_engine import QueryEngine

        engine = QueryEngine(driver)
        return engine.execute(cypher, limit=100)

    @mcp.tool()
    def nl_query(question: str) -> dict:
        """Ask a natural language question about the binary graph."""
        from revgraph.nl2gql.translator import NL2CypherTranslator

        translator = NL2CypherTranslator(llm, driver)
        cypher, results = translator.translate_and_execute(question)
        return {"cypher": cypher, "results": results[:50]}

    @mcp.tool()
    def get_schema() -> str:
        """Get the current graph schema description."""
        from revgraph.nl2gql.schema_prompt import get_schema_prompt

        return get_schema_prompt(driver)

    @mcp.tool()
    def list_binaries() -> list[dict]:
        """List all binaries loaded in the graph."""
        from revgraph.graph.query_engine import QueryEngine

        engine = QueryEngine(driver)
        return engine.execute(
            "MATCH (b:BinaryFile) "
            "OPTIONAL MATCH (b)-[:DEFINES]->(f:Function) "
            "RETURN b.name AS name, b.sha256 AS sha256, "
            "b.architecture AS architecture, count(f) AS functions "
            "ORDER BY b.name"
        )

    @mcp.tool()
    def find_callers(function_address: int, binary_sha256: str) -> list[dict]:
        """Find all functions that call the given function."""
        from revgraph.graph.query_engine import QueryEngine

        engine = QueryEngine(driver)
        return engine.execute(
            "MATCH (caller:Function)-[:CALLS]->"
            "(f:Function {address: $addr, binary_sha256: $sha256}) "
            "RETURN caller.name AS name, caller.address AS address",
            params={"addr": function_address, "sha256": binary_sha256},
        )

    @mcp.tool()
    def find_callees(function_address: int, binary_sha256: str) -> list[dict]:
        """Find all functions called by the given function."""
        from revgraph.graph.query_engine import QueryEngine

        engine = QueryEngine(driver)
        return engine.execute(
            "MATCH (f:Function {address: $addr, binary_sha256: $sha256})"
            "-[:CALLS]->(callee:Function) "
            "RETURN callee.name AS name, callee.address AS address",
            params={"addr": function_address, "sha256": binary_sha256},
        )

    @mcp.tool()
    def get_bbr_top(binary_sha256: str, limit: int = 20) -> list[dict]:
        """Get top functions by BBR (Basic Block Rank) score."""
        from revgraph.analysis.bbr import get_top_bbr_functions

        return get_top_bbr_functions(driver, binary_sha256, limit=limit)

    return mcp
