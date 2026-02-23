"""Tool registry for agent workflows with plugin discovery."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from neo4j import Driver

from revgraph.llm.client import LLMClient


@dataclass
class ToolDefinition:
    name: str
    description: str
    func: Callable[..., Any]
    parameters: dict[str, Any] = field(default_factory=dict)


class ToolRegistry:
    """Registry of tools available to agents."""

    def __init__(self, driver: Driver, llm: LLMClient) -> None:
        self._driver = driver
        self._llm = llm
        self._tools: dict[str, ToolDefinition] = {}
        self._register_defaults()

    def register(self, tool: ToolDefinition) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> ToolDefinition | None:
        return self._tools.get(name)

    def list_tools(self) -> list[ToolDefinition]:
        return list(self._tools.values())

    def get_tool_schemas(self) -> list[dict[str, Any]]:
        """Get OpenAI-compatible function schemas for all tools."""
        schemas = []
        for tool in self._tools.values():
            schema = {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters or {"type": "object", "properties": {}},
                },
            }
            schemas.append(schema)
        return schemas

    def get_tool_schemas_by_name(self, names: list[str]) -> list[dict[str, Any]]:
        """Get OpenAI-compatible schemas for a specific subset of tools."""
        schemas = []
        for name in names:
            tool = self._tools.get(name)
            if tool:
                schemas.append(
                    {
                        "type": "function",
                        "function": {
                            "name": tool.name,
                            "description": tool.description,
                            "parameters": tool.parameters or {"type": "object", "properties": {}},
                        },
                    }
                )
        return schemas

    def make_tool_executor(self) -> Callable[[str, dict[str, Any]], str]:
        """Return a ``(name, args) -> str`` callable for use with ``LLMClient.tool_loop``.

        The returned function executes the named tool and JSON-serialises
        the result.  This bridges *LLMClient* (knows nothing about the
        registry) with *ToolRegistry* (knows nothing about the LLM).
        """

        def _execute(name: str, args: dict[str, Any]) -> str:
            tool = self._tools.get(name)
            if not tool:
                return json.dumps({"error": f"Unknown tool: {name}"})
            result = tool.func(**args)
            return json.dumps(result, default=str)

        return _execute

    def execute(self, name: str, **kwargs: Any) -> Any:
        """Execute a registered tool."""
        tool = self._tools.get(name)
        if not tool:
            raise ValueError(f"Unknown tool: {name}")
        return tool.func(**kwargs)

    def _register_defaults(self) -> None:
        """Register all default tools."""
        from revgraph.agents import tools as t

        driver = self._driver
        llm = self._llm

        # --- Existing high-level tools ---

        self.register(
            ToolDefinition(
                name="load_binary_info",
                description="Load binary metadata from the graph",
                func=lambda sha256: t.load_binary_info(driver, sha256),
                parameters={
                    "type": "object",
                    "properties": {
                        "sha256": {"type": "string", "description": "Binary SHA256 hash"}
                    },
                    "required": ["sha256"],
                },
            )
        )

        self.register(
            ToolDefinition(
                name="query_graph",
                description="Execute a Cypher query against the Neo4j graph",
                func=lambda cypher: t.query_graph(driver, cypher),
                parameters={
                    "type": "object",
                    "properties": {"cypher": {"type": "string", "description": "Cypher query"}},
                    "required": ["cypher"],
                },
            )
        )

        self.register(
            ToolDefinition(
                name="nl_query",
                description="Ask a natural language question about the binary graph",
                func=lambda question: t.nl_query(driver, llm, question),
                parameters={
                    "type": "object",
                    "properties": {
                        "question": {
                            "type": "string",
                            "description": "Natural language question",
                        },
                    },
                    "required": ["question"],
                },
            )
        )

        self.register(
            ToolDefinition(
                name="compute_bbr",
                description="Compute Basic Block Rank (PageRank) scores for a binary",
                func=lambda sha256: t.compute_bbr(driver, sha256),
                parameters={
                    "type": "object",
                    "properties": {"sha256": {"type": "string"}},
                    "required": ["sha256"],
                },
            )
        )

        self.register(
            ToolDefinition(
                name="find_similar",
                description="Find functions similar to a given function by embedding",
                func=lambda function, top_k=10: t.find_similar_functions(driver, function, top_k),
                parameters={
                    "type": "object",
                    "properties": {
                        "function": {"type": "string", "description": "Function name or address"},
                        "top_k": {"type": "integer", "default": 10},
                    },
                    "required": ["function"],
                },
            )
        )

        self.register(
            ToolDefinition(
                name="get_dangerous_functions",
                description="Find functions that use dangerous APIs (strcpy, sprintf, etc.)",
                func=lambda sha256: t.get_dangerous_functions(driver, sha256),
                parameters={
                    "type": "object",
                    "properties": {"sha256": {"type": "string"}},
                    "required": ["sha256"],
                },
            )
        )

        self.register(
            ToolDefinition(
                name="summarize_function",
                description="Generate a natural language summary of a function",
                func=lambda target: t.summarize_function(driver, llm, target),
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Function address or name",
                        },
                    },
                    "required": ["target"],
                },
            )
        )

        self.register(
            ToolDefinition(
                name="generate_yara_rule",
                description="Generate YARA detection rules for a binary",
                func=lambda sha256: t.generate_yara_rule(driver, llm, sha256),
                parameters={
                    "type": "object",
                    "properties": {"sha256": {"type": "string"}},
                    "required": ["sha256"],
                },
            )
        )

        # --- Granular graph-navigation tools ---

        self.register(
            ToolDefinition(
                name="get_function_details",
                description="Get decompiled code and metadata for a single function by address",
                func=lambda address, sha256: t.get_function_details(driver, address, sha256),
                parameters={
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "Function address (hex or decimal)",
                        },
                        "sha256": {"type": "string", "description": "Binary SHA256 hash"},
                    },
                    "required": ["address", "sha256"],
                },
            )
        )

        self.register(
            ToolDefinition(
                name="get_function_strings",
                description="Get strings referenced by a single function",
                func=lambda address, sha256: t.get_function_strings(driver, address, sha256),
                parameters={
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "Function address (hex or decimal)",
                        },
                        "sha256": {"type": "string", "description": "Binary SHA256 hash"},
                    },
                    "required": ["address", "sha256"],
                },
            )
        )

        self.register(
            ToolDefinition(
                name="get_function_imports",
                description="Get imports referenced by a single function",
                func=lambda address, sha256: t.get_function_imports(driver, address, sha256),
                parameters={
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "Function address (hex or decimal)",
                        },
                        "sha256": {"type": "string", "description": "Binary SHA256 hash"},
                    },
                    "required": ["address", "sha256"],
                },
            )
        )

        self.register(
            ToolDefinition(
                name="list_functions",
                description="List functions in a binary with pagination",
                func=lambda sha256, offset=0, limit=20: t.list_functions(
                    driver, sha256, offset, limit
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "sha256": {"type": "string", "description": "Binary SHA256 hash"},
                        "offset": {
                            "type": "integer",
                            "default": 0,
                            "description": "Pagination offset",
                        },
                        "limit": {
                            "type": "integer",
                            "default": 20,
                            "description": "Max results to return",
                        },
                    },
                    "required": ["sha256"],
                },
            )
        )

        self.register(
            ToolDefinition(
                name="get_basic_blocks",
                description="Get basic blocks (CFG) for a single function",
                func=lambda address, sha256: t.get_basic_blocks(driver, address, sha256),
                parameters={
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "Function address (hex or decimal)",
                        },
                        "sha256": {"type": "string", "description": "Binary SHA256 hash"},
                    },
                    "required": ["address", "sha256"],
                },
            )
        )

        self.register(
            ToolDefinition(
                name="get_instructions",
                description="Get assembly instructions within a single basic block",
                func=lambda block_address, sha256: t.get_instructions(
                    driver, block_address, sha256
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "block_address": {
                            "type": "string",
                            "description": "Basic block address (hex or decimal)",
                        },
                        "sha256": {"type": "string", "description": "Binary SHA256 hash"},
                    },
                    "required": ["block_address", "sha256"],
                },
            )
        )

        self.register(
            ToolDefinition(
                name="search_strings",
                description="Search strings in a binary by substring match",
                func=lambda query, sha256, limit=20: t.search_strings(driver, query, sha256, limit),
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Substring to search for"},
                        "sha256": {"type": "string", "description": "Binary SHA256 hash"},
                        "limit": {"type": "integer", "default": 20},
                    },
                    "required": ["query", "sha256"],
                },
            )
        )

        self.register(
            ToolDefinition(
                name="search_functions",
                description="Search functions by name pattern in a binary",
                func=lambda query, sha256, limit=20: t.search_functions(
                    driver, query, sha256, limit
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Name pattern to search for"},
                        "sha256": {"type": "string", "description": "Binary SHA256 hash"},
                        "limit": {"type": "integer", "default": 20},
                    },
                    "required": ["query", "sha256"],
                },
            )
        )

        self.register(
            ToolDefinition(
                name="get_function_callers",
                description="Get functions that call the given function",
                func=lambda address, sha256: t.get_function_callers(driver, address, sha256),
                parameters={
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "Function address (hex or decimal)",
                        },
                        "sha256": {"type": "string", "description": "Binary SHA256 hash"},
                    },
                    "required": ["address", "sha256"],
                },
            )
        )

        self.register(
            ToolDefinition(
                name="get_function_callees",
                description="Get functions called by the given function",
                func=lambda address, sha256: t.get_function_callees(driver, address, sha256),
                parameters={
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "Function address (hex or decimal)",
                        },
                        "sha256": {"type": "string", "description": "Binary SHA256 hash"},
                    },
                    "required": ["address", "sha256"],
                },
            )
        )
