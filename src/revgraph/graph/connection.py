"""Neo4j driver management."""

from __future__ import annotations

from neo4j import GraphDatabase, Driver

from revgraph.config.models import Neo4jConfig
from revgraph.utils.logging import get_logger

log = get_logger(__name__)


def create_driver(config: Neo4jConfig) -> Driver:
    """Create and verify a Neo4j driver connection."""
    driver = GraphDatabase.driver(
        config.uri,
        auth=(config.username, config.password),
        max_connection_pool_size=config.max_connection_pool_size,
    )
    driver.verify_connectivity()
    log.info("neo4j_connected", uri=config.uri)
    return driver


def check_connectivity(driver: Driver) -> bool:
    """Check if the Neo4j connection is alive."""
    try:
        driver.verify_connectivity()
        return True
    except Exception:
        return False
