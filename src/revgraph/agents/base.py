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
        schemas = []
        for name in tool_names:
            tool = self._registry.get(name)
            if tool:
                schemas.append(
                    {
                        "type": "function",
                        "function": {
                            "name": tool.name,
                            "description": tool.description,
                            "parameters": tool.parameters,
                        },
                    }
                )
        return schemas
