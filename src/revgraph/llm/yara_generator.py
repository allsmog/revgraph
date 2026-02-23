"""YARA rule generation using LLM."""

from __future__ import annotations

from typing import Any

from neo4j import Driver

from revgraph.llm.client import LLMClient
from revgraph.llm.prompts import YARA_GENERATE
from revgraph.utils.logging import get_logger

log = get_logger(__name__)


class YARAGenerator:
    """Generate YARA rules for binary detection."""

    def __init__(self, llm: LLMClient, driver: Driver) -> None:
        self._llm = llm
        self._driver = driver

    def generate(self, sha256: str) -> str:
        """Generate YARA rules for a binary."""
        binary_info = self._get_binary_info(sha256)
        if not binary_info:
            return f"// Binary {sha256} not found"

        strings = self._get_notable_strings(sha256)
        imports = self._get_notable_imports(sha256)
        opcodes = self._get_distinctive_opcodes(sha256)

        prompt = YARA_GENERATE.render(
            name=binary_info["name"],
            architecture=binary_info.get("architecture", "unknown"),
            strings=strings,
            imports=imports,
            unique_opcodes=opcodes,
        )

        rules = self._llm.complete(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=4096,
        )

        # Clean output
        rules = rules.strip()
        if rules.startswith("```"):
            lines = rules.split("\n")
            rules = "\n".join(lines[1:])
            if rules.endswith("```"):
                rules = rules[:-3].strip()

        log.info("yara_generated", sha256=sha256[:12])
        return rules

    def _get_binary_info(self, sha256: str) -> dict[str, Any] | None:
        with self._driver.session() as session:
            result = session.run(
                "MATCH (b:BinaryFile {sha256: $sha256}) "
                "RETURN b.name AS name, b.architecture AS architecture",
                sha256=sha256,
            )
            record = result.single()
            return dict(record) if record else None

    def _get_notable_strings(self, sha256: str, limit: int = 30) -> list[str]:
        with self._driver.session() as session:
            result = session.run(
                "MATCH (s:String {binary_sha256: $sha256}) "
                "WHERE size(s.value) > 4 AND size(s.value) < 200 "
                "RETURN s.value AS value ORDER BY s.bbr_score DESC LIMIT $limit",
                sha256=sha256,
                limit=limit,
            )
            return [r["value"] for r in result]

    def _get_notable_imports(self, sha256: str) -> list[str]:
        with self._driver.session() as session:
            result = session.run(
                "MATCH (i:Import {binary_sha256: $sha256}) "
                "RETURN DISTINCT i.name AS name ORDER BY i.name",
                sha256=sha256,
            )
            return [r["name"] for r in result]

    def _get_distinctive_opcodes(
        self, sha256: str, limit: int = 10
    ) -> list[str]:
        """Get distinctive opcode sequences from high-BBR blocks."""
        with self._driver.session() as session:
            result = session.run(
                "MATCH (bb:BasicBlock {binary_sha256: $sha256})-[:CONTAINS]->(i:Instruction) "
                "WHERE bb.bbr_score IS NOT NULL "
                "WITH bb, collect(i.mnemonic) AS mnemonics "
                "ORDER BY bb.bbr_score DESC LIMIT $limit "
                "RETURN mnemonics",
                sha256=sha256,
                limit=limit,
            )
            return [" ".join(r["mnemonics"]) for r in result if r["mnemonics"]]
