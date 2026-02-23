"""RevGraph — Reverse Engineering Graph Intelligence Toolkit."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from revgraph.version import __version__

if TYPE_CHECKING:
    from neo4j import Driver

    from revgraph.config.models import RevGraphConfig
    from revgraph.llm.client import LLMClient


@dataclass
class RevGraphContext:
    """Dependency-injection container shared across CLI commands."""

    config: RevGraphConfig | None = None
    neo4j_driver: Driver | None = None
    llm_client: LLMClient | None = None
    model_override: str | None = None
    _loaded_binaries: dict[str, str] = field(default_factory=dict)

    def ensure_config(self) -> RevGraphConfig:
        if self.config is None:
            from revgraph.config.loader import load_config

            self.config = load_config()
        return self.config

    def ensure_neo4j(self) -> Driver:
        if self.neo4j_driver is None:
            from revgraph.graph.connection import create_driver

            cfg = self.ensure_config()
            self.neo4j_driver = create_driver(cfg.neo4j)
        return self.neo4j_driver

    def ensure_llm(self) -> LLMClient:
        if self.llm_client is None:
            from revgraph.llm.client import LLMClient

            cfg = self.ensure_config()
            if self.model_override:
                cfg.llm.default_model = self.model_override
            self.llm_client = LLMClient(cfg.llm)
        return self.llm_client

    def close(self) -> None:
        if self.neo4j_driver is not None:
            self.neo4j_driver.close()
            self.neo4j_driver = None


__all__ = ["RevGraphContext", "__version__"]
