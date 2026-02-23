"""Tool registry for agent workflows with plugin discovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

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

        self.register(ToolDefinition(
            name="load_binary_info",
            description="Load binary metadata from the graph",
            func=lambda sha256: t.load_binary_info(driver, sha256),
            parameters={
                "type": "object",
                "properties": {"sha256": {"type": "string", "description": "Binary SHA256 hash"}},
                "required": ["sha256"],
            },
        ))

        self.register(ToolDefinition(
            name="query_graph",
            description="Execute a Cypher query against the Neo4j graph",
            func=lambda cypher: t.query_graph(driver, cypher),
            parameters={
                "type": "object",
                "properties": {"cypher": {"type": "string", "description": "Cypher query"}},
                "required": ["cypher"],
            },
        ))

        self.register(ToolDefinition(
            name="nl_query",
            description="Ask a natural language question about the binary graph",
            func=lambda question: t.nl_query(driver, llm, question),
            parameters={
                "type": "object",
                "properties": {"question": {"type": "string", "description": "Natural language question"}},
                "required": ["question"],
            },
        ))

        self.register(ToolDefinition(
            name="compute_bbr",
            description="Compute Basic Block Rank (PageRank) scores for a binary",
            func=lambda sha256: t.compute_bbr(driver, sha256),
            parameters={
                "type": "object",
                "properties": {"sha256": {"type": "string"}},
                "required": ["sha256"],
            },
        ))

        self.register(ToolDefinition(
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
        ))

        self.register(ToolDefinition(
            name="get_dangerous_functions",
            description="Find functions that use dangerous APIs (strcpy, sprintf, etc.)",
            func=lambda sha256: t.get_dangerous_functions(driver, sha256),
            parameters={
                "type": "object",
                "properties": {"sha256": {"type": "string"}},
                "required": ["sha256"],
            },
        ))

        self.register(ToolDefinition(
            name="summarize_function",
            description="Generate a natural language summary of a function",
            func=lambda target: t.summarize_function(driver, llm, target),
            parameters={
                "type": "object",
                "properties": {"target": {"type": "string", "description": "Function address or name"}},
                "required": ["target"],
            },
        ))

        self.register(ToolDefinition(
            name="generate_yara_rule",
            description="Generate YARA detection rules for a binary",
            func=lambda sha256: t.generate_yara_rule(driver, llm, sha256),
            parameters={
                "type": "object",
                "properties": {"sha256": {"type": "string"}},
                "required": ["sha256"],
            },
        ))
