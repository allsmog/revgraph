"""MCP server for embedding and similarity operations."""

from __future__ import annotations

from neo4j import Driver

from mcp.server.fastmcp import FastMCP

from revgraph.llm.client import LLMClient


def create_embedding_server(driver: Driver, llm: LLMClient) -> FastMCP:
    mcp = FastMCP("revgraph-embedding")

    @mcp.tool()
    def embed_function(
        function_address: int, binary_sha256: str, model: str = "text-embedding-3-large"
    ) -> dict:
        """Generate an embedding for a single function."""
        from revgraph.embeddings.generator import EmbeddingGenerator
        from revgraph.embeddings.store import EmbeddingStore

        generator = EmbeddingGenerator(llm, model=model)
        embeddings = generator.generate_for_binary(
            driver, binary_sha256, scope="functions"
        )

        # Find the specific function's embedding
        for emb in embeddings:
            if emb.source_address == function_address:
                store = EmbeddingStore(driver)
                store.write_embeddings([emb], binary_sha256)
                return {
                    "address": hex(function_address),
                    "dimensions": len(emb.vector),
                    "model": emb.model,
                    "stored": True,
                }

        return {"error": f"Function at {hex(function_address)} not found"}

    @mcp.tool()
    def find_similar(
        function: str, top_k: int = 10, cross_binary: bool = False
    ) -> list[dict]:
        """Find functions similar to the given function by embedding distance."""
        from revgraph.embeddings.similarity import find_similar as _find

        return _find(driver, function, cross_binary=cross_binary, top_k=top_k)

    @mcp.tool()
    def cross_binary_similar(
        function: str, top_k: int = 10
    ) -> list[dict]:
        """Find similar functions across all loaded binaries."""
        from revgraph.embeddings.similarity import find_similar as _find

        return _find(driver, function, cross_binary=True, top_k=top_k)

    @mcp.tool()
    def cluster_functions(
        method: str = "hdbscan", n_clusters: int = 10
    ) -> dict:
        """Cluster all functions by embedding similarity."""
        from revgraph.analysis.clustering import cluster_functions as _cluster

        result = _cluster(driver, method=method, n_clusters=n_clusters)
        # Simplify for MCP output
        clusters = []
        for c in result.get("clusters", []):
            clusters.append(
                {
                    "id": c["id"],
                    "size": c["size"],
                    "representative": c.get("representative", ""),
                }
            )
        return {
            "n_clusters": result["n_clusters"],
            "n_functions": result["n_functions"],
            "method": result["method"],
            "clusters": clusters,
        }

    return mcp
