"""Function and binary summarization using LLM."""

from __future__ import annotations

from typing import Any

from neo4j import Driver

from revgraph.agents.registry import ToolRegistry
from revgraph.llm.client import LLMClient
from revgraph.llm.prompts import AGENT_SUMMARIZE_BINARY, AGENT_SUMMARIZE_FUNCTION
from revgraph.utils.logging import get_logger

log = get_logger(__name__)

_FUNCTION_TOOLS = [
    "get_function_details",
    "get_function_strings",
    "get_function_imports",
    "get_function_callers",
    "get_function_callees",
]

_BINARY_TOOLS = [
    "load_binary_info",
    "list_functions",
    "compute_bbr",
    "search_strings",
    "get_function_details",
    "get_function_strings",
    "get_function_imports",
    "get_function_callers",
    "get_function_callees",
]


class Summarizer:
    """Generate natural language summaries for functions and binaries."""

    def __init__(
        self, llm: LLMClient, driver: Driver, registry: ToolRegistry | None = None,
    ) -> None:
        self._llm = llm
        self._driver = driver
        self._registry = registry or ToolRegistry(driver, llm)

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
        """Summarize a single function via agentic tool loop."""
        ref = self._resolve_function_ref(address_or_name)
        if not ref:
            return {"summary": f"Function '{address_or_name}' not found", "error": True}

        address, sha256, name = ref

        messages = [
            {"role": "system", "content": AGENT_SUMMARIZE_FUNCTION},
            {
                "role": "user",
                "content": (
                    f"Summarize the function at address {address} "
                    f"in binary {sha256}."
                ),
            },
        ]

        tools = self._registry.get_tool_schemas_by_name(_FUNCTION_TOOLS)
        executor = self._registry.make_tool_executor()

        summary = self._llm.tool_loop(
            messages=messages,
            tools=tools,
            tool_executor=executor,
            temperature=0.1,
            max_iterations=8,
        )

        return {
            "name": name,
            "address": address,
            "summary": summary,
        }

    def _summarize_binary(self, sha256: str) -> dict[str, Any]:
        """Summarize an entire binary via agentic tool loop."""
        messages = [
            {"role": "system", "content": AGENT_SUMMARIZE_BINARY},
            {
                "role": "user",
                "content": f"Summarize the binary with SHA256: {sha256}",
            },
        ]

        tools = self._registry.get_tool_schemas_by_name(_BINARY_TOOLS)
        executor = self._registry.make_tool_executor()

        summary = self._llm.tool_loop(
            messages=messages,
            tools=tools,
            tool_executor=executor,
            temperature=0.1,
            max_iterations=15,
        )

        # Try to get the binary name for the return value
        name = sha256[:12]
        with self._driver.session() as session:
            result = session.run(
                "MATCH (b:BinaryFile {sha256: $sha256}) RETURN b.name AS name",
                sha256=sha256,
            )
            record = result.single()
            if record:
                name = record["name"]

        return {
            "name": name,
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

    def _resolve_function_ref(self, identifier: str) -> tuple[str, str, str] | None:
        """Resolve a function to (address_hex, sha256, name) for seeding the tool loop."""
        with self._driver.session() as session:
            # Try address
            try:
                addr = int(identifier, 16) if identifier.startswith("0x") else int(identifier)
                result = session.run(
                    "MATCH (f:Function {address: $addr}) "
                    "RETURN f.name AS name, f.address AS address, "
                    "f.binary_sha256 AS sha256",
                    addr=addr,
                )
                record = result.single()
                if record and record["name"]:
                    return (hex(record["address"]), record["sha256"], record["name"])
            except ValueError:
                pass

            # Try name
            result = session.run(
                "MATCH (f:Function {name: $name}) "
                "RETURN f.name AS name, f.address AS address, "
                "f.binary_sha256 AS sha256",
                name=identifier,
            )
            record = result.single()
            if record and record["name"]:
                return (hex(record["address"]), record["sha256"], record["name"])

        return None
