"""Function and binary summarization using LLM."""

from __future__ import annotations

from typing import Any

from neo4j import Driver

from revgraph.llm.client import LLMClient
from revgraph.llm.prompts import SUMMARIZE_BINARY, SUMMARIZE_FUNCTION
from revgraph.utils.logging import get_logger

log = get_logger(__name__)


class Summarizer:
    """Generate natural language summaries for functions and binaries."""

    def __init__(self, llm: LLMClient, driver: Driver) -> None:
        self._llm = llm
        self._driver = driver

    def summarize(
        self, target: str, scope: str = "function"
    ) -> dict[str, Any]:
        if scope == "function":
            return self._summarize_function(target)
        elif scope == "binary":
            return self._summarize_binary(target)
        else:
            raise ValueError(f"Unknown scope: {scope}")

    def _summarize_function(self, address_or_name: str) -> dict[str, Any]:
        """Summarize a single function."""
        func = self._resolve_function(address_or_name)
        if not func:
            return {"summary": f"Function '{address_or_name}' not found", "error": True}

        prompt = SUMMARIZE_FUNCTION.render(
            name=func["name"],
            address=hex(func["address"]) if isinstance(func["address"], int) else func["address"],
            decompiled_code=func.get("decompiled_code", ""),
            strings=func.get("strings", []),
            imports=func.get("imports", []),
            callers=func.get("callers", []),
            callees=func.get("callees", []),
        )

        summary = self._llm.complete(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
        )

        return {
            "name": func["name"],
            "address": func["address"],
            "summary": summary,
        }

    def _summarize_binary(self, sha256: str) -> dict[str, Any]:
        """Summarize an entire binary."""
        with self._driver.session() as session:
            # Binary info
            result = session.run(
                "MATCH (b:BinaryFile {sha256: $sha256}) "
                "RETURN b.name AS name, b.architecture AS architecture, "
                "b.file_type AS file_type",
                sha256=sha256,
            )
            binary = result.single()
            if not binary:
                return {"summary": f"Binary '{sha256}' not found", "error": True}

            # Function count
            result = session.run(
                "MATCH (b:BinaryFile {sha256: $sha256})-[:DEFINES]->(f:Function) "
                "RETURN count(f) AS cnt",
                sha256=sha256,
            )
            num_functions = result.single()["cnt"]

            # Top functions by BBR
            result = session.run(
                "MATCH (f:Function {binary_sha256: $sha256})-[:CONTAINS]->(bb:BasicBlock) "
                "WHERE bb.bbr_score IS NOT NULL "
                "WITH f, max(bb.bbr_score) AS max_bbr "
                "RETURN f.name AS name, f.address AS address, "
                "f.summary AS summary, max_bbr "
                "ORDER BY max_bbr DESC LIMIT 10",
                sha256=sha256,
            )
            top_functions = [dict(r) for r in result]

            # Notable imports
            result = session.run(
                "MATCH (f:Function {binary_sha256: $sha256})-[:REFERENCES_IMPORT]->(i:Import) "
                "RETURN DISTINCT i.name AS name ORDER BY i.name",
                sha256=sha256,
            )
            imports = [r["name"] for r in result]

            # Notable strings
            result = session.run(
                "MATCH (s:String {binary_sha256: $sha256}) "
                "RETURN s.value AS value ORDER BY s.value LIMIT 30",
                sha256=sha256,
            )
            strings = [r["value"] for r in result]

        prompt = SUMMARIZE_BINARY.render(
            name=binary["name"],
            architecture=binary["architecture"],
            file_type=binary["file_type"],
            sha256=sha256,
            num_functions=num_functions,
            top_functions=top_functions,
            imports=imports,
            strings=strings,
        )

        summary = self._llm.complete(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
        )

        return {
            "name": binary["name"],
            "sha256": sha256,
            "summary": summary,
        }

    def write_summary(
        self, target: str, summary: str, scope: str = "function"
    ) -> None:
        """Write a summary back to the graph."""
        with self._driver.session() as session:
            if scope == "function":
                try:
                    addr = int(target, 16) if target.startswith("0x") else int(target)
                    session.run(
                        "MATCH (f:Function {address: $addr}) SET f.summary = $summary",
                        addr=addr,
                        summary=summary,
                    )
                except ValueError:
                    session.run(
                        "MATCH (f:Function {name: $name}) SET f.summary = $summary",
                        name=target,
                        summary=summary,
                    )

    def _resolve_function(self, identifier: str) -> dict[str, Any] | None:
        """Resolve a function by address or name."""
        with self._driver.session() as session:
            # Try address
            try:
                addr = int(identifier, 16) if identifier.startswith("0x") else int(identifier)
                result = session.run(
                    "MATCH (f:Function {address: $addr}) "
                    "OPTIONAL MATCH (f)-[:REFERENCES_STRING]->(s:String) "
                    "OPTIONAL MATCH (f)-[:REFERENCES_IMPORT]->(i:Import) "
                    "OPTIONAL MATCH (caller:Function)-[:CALLS]->(f) "
                    "OPTIONAL MATCH (f)-[:CALLS]->(callee:Function) "
                    "RETURN f.name AS name, f.address AS address, "
                    "f.decompiled_code AS decompiled_code, "
                    "collect(DISTINCT s.value) AS strings, "
                    "collect(DISTINCT i.name) AS imports, "
                    "collect(DISTINCT caller.name) AS callers, "
                    "collect(DISTINCT callee.name) AS callees",
                    addr=addr,
                )
                record = result.single()
                if record and record["name"]:
                    return dict(record)
            except ValueError:
                pass

            # Try name
            result = session.run(
                "MATCH (f:Function {name: $name}) "
                "OPTIONAL MATCH (f)-[:REFERENCES_STRING]->(s:String) "
                "OPTIONAL MATCH (f)-[:REFERENCES_IMPORT]->(i:Import) "
                "OPTIONAL MATCH (caller:Function)-[:CALLS]->(f) "
                "OPTIONAL MATCH (f)-[:CALLS]->(callee:Function) "
                "RETURN f.name AS name, f.address AS address, "
                "f.decompiled_code AS decompiled_code, "
                "collect(DISTINCT s.value) AS strings, "
                "collect(DISTINCT i.name) AS imports, "
                "collect(DISTINCT caller.name) AS callers, "
                "collect(DISTINCT callee.name) AS callees",
                name=identifier,
            )
            record = result.single()
            if record and record["name"]:
                return dict(record)

        return None
