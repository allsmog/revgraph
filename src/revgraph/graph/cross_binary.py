"""Cross-binary analysis queries."""

from __future__ import annotations

from typing import Any

from neo4j import Driver

from revgraph.utils.logging import get_logger

log = get_logger(__name__)


def find_shared_functions(
    driver: Driver, sha256_a: str, sha256_b: str
) -> list[dict[str, Any]]:
    """Find functions with the same name across two binaries."""
    query = """
    MATCH (f1:Function {binary_sha256: $sha_a})
    MATCH (f2:Function {binary_sha256: $sha_b})
    WHERE f1.name = f2.name
    RETURN f1.name AS name, f1.address AS address_a, f2.address AS address_b,
           f1.size AS size_a, f2.size AS size_b
    ORDER BY f1.name
    """
    with driver.session() as session:
        result = session.run(query, sha_a=sha256_a, sha_b=sha256_b)
        return [dict(r) for r in result]


def find_shared_imports(
    driver: Driver, sha256_a: str, sha256_b: str
) -> list[dict[str, Any]]:
    """Find imports referenced by both binaries."""
    query = """
    MATCH (f1:Function {binary_sha256: $sha_a})-[:REFERENCES_IMPORT]->(i:Import)
          <-[:REFERENCES_IMPORT]-(f2:Function {binary_sha256: $sha_b})
    RETURN DISTINCT i.name AS import_name, i.library AS library,
           collect(DISTINCT f1.name) AS functions_a,
           collect(DISTINCT f2.name) AS functions_b
    ORDER BY i.name
    """
    with driver.session() as session:
        result = session.run(query, sha_a=sha256_a, sha_b=sha256_b)
        return [dict(r) for r in result]


def find_shared_strings(
    driver: Driver, sha256_a: str, sha256_b: str
) -> list[dict[str, Any]]:
    """Find strings referenced by both binaries."""
    query = """
    MATCH (s1:String {binary_sha256: $sha_a})
    MATCH (s2:String {binary_sha256: $sha_b})
    WHERE s1.value = s2.value
    RETURN DISTINCT s1.value AS value
    ORDER BY s1.value
    """
    with driver.session() as session:
        result = session.run(query, sha_a=sha256_a, sha_b=sha256_b)
        return [dict(r) for r in result]


def diff_functions(
    driver: Driver, sha256_a: str, sha256_b: str
) -> dict[str, list[dict[str, Any]]]:
    """Diff functions between two binaries by name."""
    query_a = """
    MATCH (f:Function {binary_sha256: $sha})
    RETURN f.name AS name, f.address AS address, f.size AS size
    """
    with driver.session() as session:
        funcs_a = {r["name"]: dict(r) for r in session.run(query_a, sha=sha256_a)}
        funcs_b = {r["name"]: dict(r) for r in session.run(query_a, sha=sha256_b)}

    names_a = set(funcs_a.keys())
    names_b = set(funcs_b.keys())

    return {
        "only_in_a": [funcs_a[n] for n in sorted(names_a - names_b)],
        "only_in_b": [funcs_b[n] for n in sorted(names_b - names_a)],
        "shared": [
            {**funcs_a[n], "size_b": funcs_b[n]["size"]}
            for n in sorted(names_a & names_b)
        ],
        "size_changed": [
            {**funcs_a[n], "size_b": funcs_b[n]["size"]}
            for n in sorted(names_a & names_b)
            if funcs_a[n]["size"] != funcs_b[n]["size"]
        ],
    }
