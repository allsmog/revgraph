"""Execute and format Cypher query results."""

from __future__ import annotations

from typing import Any

from neo4j import Driver

from revgraph.utils.logging import get_logger

log = get_logger(__name__)


class QueryEngine:
    """Thin wrapper around Neo4j sessions for executing Cypher queries."""

    def __init__(self, driver: Driver) -> None:
        self._driver = driver

    def execute(
        self,
        query: str,
        params: dict[str, Any] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a Cypher query and return results as list of dicts."""
        params = params or {}
        if limit is not None and "LIMIT" not in query.upper():
            query = query.rstrip().rstrip(";") + f"\nLIMIT {limit}"

        log.debug("executing_query", query=query[:200], params=params)

        with self._driver.session() as session:
            result = session.run(query, **params)
            records = [dict(record) for record in result]

        log.debug("query_results", count=len(records))
        return records

    def execute_write(
        self,
        query: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a write query and return counters."""
        params = params or {}

        with self._driver.session() as session:
            result = session.run(query, **params)
            summary = result.consume()

        counters = summary.counters
        return {
            "nodes_created": counters.nodes_created,
            "relationships_created": counters.relationships_created,
            "properties_set": counters.properties_set,
        }

    def execute_named(
        self,
        query_template: str,
        params: dict[str, Any] | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Execute a named query from the query library."""
        params = params or {}
        params.setdefault("limit", limit)
        return self.execute(query_template, params)
