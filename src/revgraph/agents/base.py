"""Base workflow class for agent teams."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from neo4j import Driver

from revgraph.agents.registry import ToolRegistry
from revgraph.config.models import RevGraphConfig
from revgraph.llm.client import LLMClient


class BaseWorkflow(ABC):
    """Base class for agent workflows."""

    name: str = "base"
    description: str = "Base workflow"
    agents: list[str] = []

    def __init__(
        self,
        config: RevGraphConfig,
        driver: Driver,
        llm: LLMClient,
        registry: ToolRegistry,
    ) -> None:
        self._config = config
        self._driver = driver
        self._llm = llm
        self._registry = registry

    @abstractmethod
    async def run(
        self,
        input_text: str,
        max_turns: int = 30,
        interactive: bool = False,
    ) -> str:
        """Execute the workflow and return final output."""
        ...

    def _get_tool_schemas(self, tool_names: list[str]) -> list[dict[str, Any]]:
        """Get tool schemas for specific tools."""
        return self._registry.get_tool_schemas_by_name(tool_names)

    def _run_agent(
        self,
        system_prompt: str,
        user_msg: str,
        tool_names: list[str],
        max_iterations: int = 15,
    ) -> str:
        """Run a single-agent tool loop.

        Builds tool schemas and executor from the registry, then delegates
        to ``LLMClient.tool_loop``.
        """
        tools = self._registry.get_tool_schemas_by_name(tool_names)
        executor = self._registry.make_tool_executor()

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_msg},
        ]

        return self._llm.tool_loop(
            messages=messages,
            tools=tools,
            tool_executor=executor,
            temperature=0.1,
            max_iterations=max_iterations,
        )
