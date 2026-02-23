"""Read/write embeddings in Neo4j."""

from __future__ import annotations

import uuid
from typing import Any

from neo4j import Driver

from revgraph.embeddings.generator import EmbeddingResult
from revgraph.utils.logging import get_logger

log = get_logger(__name__)


class EmbeddingStore:
    """Manage embedding storage in Neo4j."""

    def __init__(self, driver: Driver) -> None:
        self._driver = driver

    def write_embeddings(
        self,
        embeddings: list[EmbeddingResult],
        sha256: str,
        batch_size: int = 100,
    ) -> int:
        """Write embedding results to Neo4j as Embedding nodes linked to Functions."""
        rows = [
            {
                "id": str(uuid.uuid4()),
                "vector": emb.vector,
                "model": emb.model,
                "dimensions": len(emb.vector),
                "type": emb.source_type,
                "source_address": emb.source_address,
                "binary_sha256": sha256,
            }
            for emb in embeddings
        ]

        written = 0
        with self._driver.session() as session:
            for i in range(0, len(rows), batch_size):
                batch = rows[i : i + batch_size]
                session.run(
                    "UNWIND $rows AS r "
                    "MERGE (e:Embedding {id: r.id}) "
                    "SET e.vector = r.vector, e.model = r.model, "
                    "e.dimensions = r.dimensions, e.type = r.type, "
                    "e.source_address = r.source_address, "
                    "e.binary_sha256 = r.binary_sha256 "
                    "WITH e, r "
                    "MATCH (f:Function {address: r.source_address, binary_sha256: r.binary_sha256}) "
                    "MERGE (f)-[:HAS_EMBEDDING]->(e)",
                    rows=batch,
                )
                written += len(batch)

        log.info("embeddings_written", sha256=sha256[:12], count=written)
        return written

    def read_embeddings(
        self, sha256: str, scope: str = "functions"
    ) -> list[dict[str, Any]]:
        """Read embeddings from Neo4j for a binary."""
        with self._driver.session() as session:
            result = session.run(
                "MATCH (f:Function {binary_sha256: $sha256})"
                "-[:HAS_EMBEDDING]->(e:Embedding {type: $scope}) "
                "RETURN f.name AS name, f.address AS address, "
                "e.vector AS vector, e.model AS model",
                sha256=sha256,
                scope="function" if scope == "functions" else "block",
            )
            return [dict(r) for r in result]

    def delete_embeddings(self, sha256: str) -> int:
        """Delete all embeddings for a binary."""
        with self._driver.session() as session:
            result = session.run(
                "MATCH (e:Embedding {binary_sha256: $sha256}) "
                "DETACH DELETE e RETURN count(e) AS deleted",
                sha256=sha256,
            )
            record = result.single()
            count = record["deleted"] if record else 0
            log.info("embeddings_deleted", sha256=sha256[:12], count=count)
            return count
