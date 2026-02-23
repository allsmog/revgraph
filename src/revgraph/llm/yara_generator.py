"""YARA rule generation using LLM."""

from __future__ import annotations

from neo4j import Driver

from revgraph.agents.registry import ToolRegistry
from revgraph.llm.client import LLMClient
from revgraph.llm.prompts import AGENT_YARA_GENERATE
from revgraph.utils.logging import get_logger

log = get_logger(__name__)

_YARA_TOOLS = [
    "load_binary_info",
    "search_strings",
    "search_functions",
    "list_functions",
    "get_function_details",
    "get_function_imports",
    "get_basic_blocks",
    "get_instructions",
    "compute_bbr",
]


class YARAGenerator:
    """Generate YARA rules for binary detection."""

    def __init__(
        self, llm: LLMClient, driver: Driver, registry: ToolRegistry | None = None,
    ) -> None:
        self._llm = llm
        self._driver = driver
        self._registry = registry or ToolRegistry(driver, llm)

    def generate(self, sha256: str) -> str:
        """Generate YARA rules for a binary via agentic tool loop."""
        messages = [
            {"role": "system", "content": AGENT_YARA_GENERATE},
            {
                "role": "user",
                "content": (
                    f"Generate YARA rules for the binary with SHA256: {sha256}"
                ),
            },
        ]

        tools = self._registry.get_tool_schemas_by_name(_YARA_TOOLS)
        executor = self._registry.make_tool_executor()

        rules = self._llm.tool_loop(
            messages=messages,
            tools=tools,
            tool_executor=executor,
            temperature=0.1,
            max_tokens=4096,
            max_iterations=15,
        )

        # Clean markdown fences from output
        rules = rules.strip()
        if rules.startswith("```"):
            lines = rules.split("\n")
            rules = "\n".join(lines[1:])
            if rules.endswith("```"):
                rules = rules[:-3].strip()

        log.info("yara_generated", sha256=sha256[:12])
        return rules
