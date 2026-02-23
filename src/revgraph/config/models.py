"""Pydantic configuration models with env var support."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Neo4jConfig(BaseModel):
    uri: str = "bolt://localhost:7687"
    username: str = "neo4j"
    password: str = "changeme"
    database: str = "neo4j"
    max_connection_pool_size: int = 50


class ProviderConfig(BaseModel):
    api_base: str | None = None
    api_key: str | None = None
    extra: dict[str, str] = Field(default_factory=dict)


class LLMConfig(BaseModel):
    default_provider: str = "anthropic"
    default_model: str = "claude-sonnet-4-20250514"
    api_keys: dict[str, str] = Field(default_factory=dict)
    temperature: float = 0.1
    max_tokens: int = 4096
    providers: dict[str, ProviderConfig] = Field(default_factory=dict)


class EmbeddingsConfig(BaseModel):
    default_model: str = "text-embedding-3-large"
    dimensions: int = 3072


class BBRConfig(BaseModel):
    iterations: int = 20
    damping_factor: float = 0.85


class AnalysisConfig(BaseModel):
    bbr: BBRConfig = Field(default_factory=BBRConfig)


class AgentsConfig(BaseModel):
    team_type: str = "selector"
    max_turns: int = 30


class RevGraphConfig(BaseModel):
    neo4j: Neo4jConfig = Field(default_factory=Neo4jConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    embeddings: EmbeddingsConfig = Field(default_factory=EmbeddingsConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    agents: AgentsConfig = Field(default_factory=AgentsConfig)
