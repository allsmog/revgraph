"""Neo4j schema creation: constraints, indexes, and vector indexes."""

from __future__ import annotations

from neo4j import Driver

from revgraph.utils.logging import get_logger

log = get_logger(__name__)

CONSTRAINTS = [
    "CREATE CONSTRAINT func_addr IF NOT EXISTS FOR (f:Function) REQUIRE (f.address, f.binary_sha256) IS UNIQUE",
    "CREATE CONSTRAINT bb_addr IF NOT EXISTS FOR (b:BasicBlock) REQUIRE (b.address, b.binary_sha256) IS UNIQUE",
    "CREATE CONSTRAINT insn_addr IF NOT EXISTS FOR (i:Instruction) REQUIRE (i.address, i.binary_sha256) IS UNIQUE",
    "CREATE CONSTRAINT binary_sha IF NOT EXISTS FOR (b:BinaryFile) REQUIRE b.sha256 IS UNIQUE",
    "CREATE CONSTRAINT emb_id IF NOT EXISTS FOR (e:Embedding) REQUIRE e.id IS UNIQUE",
]

INDEXES = [
    "CREATE INDEX func_name IF NOT EXISTS FOR (f:Function) ON (f.name)",
    "CREATE INDEX func_binary IF NOT EXISTS FOR (f:Function) ON (f.binary_sha256)",
    "CREATE INDEX bb_binary IF NOT EXISTS FOR (b:BasicBlock) ON (b.binary_sha256)",
    "CREATE INDEX string_binary IF NOT EXISTS FOR (s:String) ON (s.binary_sha256)",
    "CREATE INDEX import_binary IF NOT EXISTS FOR (i:Import) ON (i.binary_sha256)",
]

FULLTEXT_INDEXES = [
    "CREATE FULLTEXT INDEX func_name_ft IF NOT EXISTS FOR (f:Function) ON EACH [f.name]",
    "CREATE FULLTEXT INDEX string_value_ft IF NOT EXISTS FOR (s:String) ON EACH [s.value]",
]

VECTOR_INDEX = (
    "CREATE VECTOR INDEX embedding_vector IF NOT EXISTS "
    "FOR (e:Embedding) ON (e.vector) "
    "OPTIONS {indexConfig: {`vector.dimensions`: 3072, `vector.similarity_function`: 'cosine'}}"
)


def create_schema(driver: Driver) -> None:
    """Create all constraints, indexes, and vector indexes."""
    with driver.session() as session:
        for stmt in CONSTRAINTS:
            try:
                session.run(stmt)
                log.info("schema_created", statement=stmt[:60])
            except Exception as exc:
                log.warning("schema_skip", statement=stmt[:60], reason=str(exc))

        for stmt in INDEXES + FULLTEXT_INDEXES:
            try:
                session.run(stmt)
                log.info("index_created", statement=stmt[:60])
            except Exception as exc:
                log.warning("index_skip", statement=stmt[:60], reason=str(exc))

        try:
            session.run(VECTOR_INDEX)
            log.info("vector_index_created")
        except Exception as exc:
            log.warning("vector_index_skip", reason=str(exc))


def drop_schema(driver: Driver) -> None:
    """Drop all constraints and indexes."""
    with driver.session() as session:
        for record in session.run("SHOW CONSTRAINTS"):
            name = record["name"]
            try:
                session.run(f"DROP CONSTRAINT {name}")
                log.info("constraint_dropped", name=name)
            except Exception:
                pass

        for record in session.run("SHOW INDEXES"):
            name = record["name"]
            try:
                session.run(f"DROP INDEX {name}")
                log.info("index_dropped", name=name)
            except Exception:
                pass


def show_schema(driver: Driver) -> str:
    """Return a human-readable schema summary."""
    lines = ["=== Graph Schema ===\n"]

    with driver.session() as session:
        lines.append("Constraints:")
        for record in session.run("SHOW CONSTRAINTS"):
            lines.append(f"  {record['name']}: {record.get('type', '')} on {record.get('labelsOrTypes', '')}")

        lines.append("\nIndexes:")
        for record in session.run("SHOW INDEXES"):
            lines.append(f"  {record['name']}: {record.get('type', '')} on {record.get('labelsOrTypes', '')}")

        lines.append("\nNode counts:")
        for label in ["BinaryFile", "Function", "BasicBlock", "Instruction", "String", "Import", "Embedding"]:
            result = session.run(f"MATCH (n:{label}) RETURN count(n) AS cnt")
            cnt = result.single()["cnt"]
            lines.append(f"  {label}: {cnt}")

    return "\n".join(lines)
