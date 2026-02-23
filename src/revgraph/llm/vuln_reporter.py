"""Vulnerability report generation using LLM."""

from __future__ import annotations

from typing import Any

from neo4j import Driver

from revgraph.analysis.vulnerability import find_dangerous_functions, vulnerability_surface
from revgraph.llm.client import LLMClient
from revgraph.llm.prompts import VULN_REPORT
from revgraph.utils.logging import get_logger

log = get_logger(__name__)


class VulnReporter:
    """Generate vulnerability reports for binaries."""

    def __init__(self, llm: LLMClient, driver: Driver) -> None:
        self._llm = llm
        self._driver = driver

    def generate_report(
        self, sha256: str, output_format: str = "markdown"
    ) -> str:
        """Generate a comprehensive vulnerability report."""
        # Gather data
        surface = vulnerability_surface(self._driver, sha256)
        binary_info = self._get_binary_info(sha256)

        if not binary_info:
            return f"Binary {sha256} not found in graph."

        # Get high-BBR functions
        high_bbr = self._get_high_bbr_functions(sha256)

        prompt = VULN_REPORT.render(
            name=binary_info["name"],
            architecture=binary_info.get("architecture", "unknown"),
            dangerous_functions=surface.get("dangerous_functions", []),
            high_bbr_functions=high_bbr,
            format=output_format,
        )

        report = self._llm.complete(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=8192,
        )

        log.info(
            "vuln_report_generated",
            sha256=sha256[:12],
            dangerous_count=surface["total_dangerous_functions"],
        )
        return report

    def _get_binary_info(self, sha256: str) -> dict[str, Any] | None:
        with self._driver.session() as session:
            result = session.run(
                "MATCH (b:BinaryFile {sha256: $sha256}) "
                "RETURN b.name AS name, b.architecture AS architecture, "
                "b.file_type AS file_type",
                sha256=sha256,
            )
            record = result.single()
            return dict(record) if record else None

    def _get_high_bbr_functions(
        self, sha256: str, limit: int = 20
    ) -> list[dict[str, Any]]:
        with self._driver.session() as session:
            result = session.run(
                "MATCH (f:Function {binary_sha256: $sha256})-[:CONTAINS]->(bb:BasicBlock) "
                "WHERE bb.bbr_score IS NOT NULL "
                "WITH f, max(bb.bbr_score) AS bbr_score "
                "RETURN f.name AS name, f.address AS address, bbr_score "
                "ORDER BY bbr_score DESC LIMIT $limit",
                sha256=sha256,
                limit=limit,
            )
            return [dict(r) for r in result]
