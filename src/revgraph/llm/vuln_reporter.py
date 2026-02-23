"""Vulnerability report generation using LLM."""

from __future__ import annotations

from neo4j import Driver

from revgraph.agents.registry import ToolRegistry
from revgraph.llm.client import LLMClient
from revgraph.llm.prompts import AGENT_VULN_REPORT
from revgraph.utils.logging import get_logger

log = get_logger(__name__)

_VULN_TOOLS = [
    "load_binary_info",
    "get_dangerous_functions",
    "compute_bbr",
    "list_functions",
    "get_function_details",
    "get_function_strings",
    "get_function_imports",
    "get_function_callers",
    "search_strings",
    "search_functions",
]


class VulnReporter:
    """Generate vulnerability reports for binaries."""

    def __init__(
        self, llm: LLMClient, driver: Driver, registry: ToolRegistry | None = None,
    ) -> None:
        self._llm = llm
        self._driver = driver
        self._registry = registry or ToolRegistry(driver, llm)

    def generate_report(
        self, sha256: str, output_format: str = "markdown"
    ) -> str:
        """Generate a comprehensive vulnerability report via agentic tool loop."""
        messages = [
            {"role": "system", "content": AGENT_VULN_REPORT},
            {
                "role": "user",
                "content": (
                    f"Generate a vulnerability report for the binary with "
                    f"SHA256: {sha256}. Output in {output_format} format."
                ),
            },
        ]

        tools = self._registry.get_tool_schemas_by_name(_VULN_TOOLS)
        executor = self._registry.make_tool_executor()

        report = self._llm.tool_loop(
            messages=messages,
            tools=tools,
            tool_executor=executor,
            temperature=0.1,
            max_tokens=8192,
            max_iterations=20,
        )

        log.info("vuln_report_generated", sha256=sha256[:12])
        return report
