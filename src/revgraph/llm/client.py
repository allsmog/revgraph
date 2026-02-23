"""LiteLLM wrapper with retry logic, routing, and token tracking."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import litellm
from tenacity import retry, stop_after_attempt, wait_exponential

from revgraph.config.models import LLMConfig
from revgraph.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def update(self, usage: dict[str, int]) -> None:
        self.prompt_tokens += usage.get("prompt_tokens", 0)
        self.completion_tokens += usage.get("completion_tokens", 0)
        self.total_tokens += usage.get("total_tokens", 0)


class LLMClient:
    """Provider-agnostic LLM client using LiteLLM."""

    def __init__(self, config: LLMConfig) -> None:
        self._config = config
        self._usage = TokenUsage()
        self._setup_api_keys()

    def _setup_api_keys(self) -> None:
        """Set API keys as environment variables for LiteLLM."""
        import os

        key_map = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "google": "GOOGLE_API_KEY",
        }
        for provider, env_var in key_map.items():
            key = self._config.api_keys.get(provider, "")
            if key and not os.environ.get(env_var):
                os.environ[env_var] = key

        for name, provider_cfg in self._config.providers.items():
            if provider_cfg.api_base:
                if name == "ollama":
                    os.environ.setdefault("OLLAMA_API_BASE", provider_cfg.api_base)

    @property
    def default_model(self) -> str:
        return self._config.default_model

    @property
    def usage(self) -> TokenUsage:
        return self._usage

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    def complete(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> str:
        """Send a completion request through LiteLLM."""
        model = model or self._config.default_model
        temperature = temperature if temperature is not None else self._config.temperature
        max_tokens = max_tokens or self._config.max_tokens

        log.debug("llm_request", model=model, messages=len(messages))

        response = litellm.completion(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )

        content = response.choices[0].message.content or ""
        if hasattr(response, "usage") and response.usage:
            self._usage.update(
                {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens,
                }
            )

        log.debug("llm_response", model=model, tokens=len(content))
        return content

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    def embed(
        self,
        texts: list[str],
        model: str | None = None,
        dimensions: int | None = None,
    ) -> list[list[float]]:
        """Generate embeddings through LiteLLM."""
        model = model or "text-embedding-3-large"

        log.debug("embedding_request", model=model, texts=len(texts))

        kwargs: dict[str, Any] = {"model": model, "input": texts}
        if dimensions:
            kwargs["dimensions"] = dimensions

        response = litellm.embedding(**kwargs)
        return [item["embedding"] for item in response.data]

    def complete_structured(
        self,
        messages: list[dict[str, str]],
        response_format: dict[str, Any] | None = None,
        model: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Completion with optional JSON response format."""
        if response_format:
            kwargs["response_format"] = response_format
        return self.complete(messages, model=model, **kwargs)
