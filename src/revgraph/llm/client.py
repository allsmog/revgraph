"""LiteLLM wrapper with retry logic, routing, and token tracking."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
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
            if provider_cfg.api_base and name == "ollama":
                os.environ.setdefault("OLLAMA_API_BASE", provider_cfg.api_base)

    @property
    def default_model(self) -> str:
        return self._config.default_model

    @property
    def usage(self) -> TokenUsage:
        return self._usage

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    def _call_litellm(
        self,
        messages: list[dict[str, Any]],
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> Any:
        """Low-level litellm.completion call with retry and token tracking."""
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

        if hasattr(response, "usage") and response.usage:
            self._usage.update(
                {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens,
                }
            )

        return response

    def complete(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> str:
        """Send a completion request through LiteLLM."""
        response = self._call_litellm(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )
        content = response.choices[0].message.content or ""
        log.debug("llm_response", model=model or self._config.default_model, tokens=len(content))
        return content

    def tool_loop(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        tool_executor: Callable[[str, dict[str, Any]], str],
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        max_iterations: int = 15,
    ) -> str:
        """Run a tool-calling loop until the model stops requesting tools.

        Args:
            messages: Conversation messages (system + user).
            tools: OpenAI-compatible tool schemas.
            tool_executor: ``(name, args) -> str`` callable that runs a tool
                and returns the JSON-serialised result.
            max_iterations: Safety cap on loop iterations.

        Returns:
            The model's final text response.
        """
        messages = list(messages)  # don't mutate caller's list

        for iteration in range(max_iterations):
            log.debug("tool_loop_iteration", iteration=iteration)

            response = self._call_litellm(
                messages=messages,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                tools=tools,
            )

            choice = response.choices[0]
            assistant_msg = choice.message

            # If no tool calls, return the text content
            tool_calls = getattr(assistant_msg, "tool_calls", None)
            if not tool_calls:
                return assistant_msg.content or ""

            # Append assistant message with tool calls
            messages.append(assistant_msg.model_dump())

            # Execute each tool call and append results
            for tc in tool_calls:
                func_name = tc.function.name
                try:
                    func_args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    func_args = {}

                log.debug("tool_call", tool=func_name, args=func_args)

                try:
                    result = tool_executor(func_name, func_args)
                except Exception as exc:
                    result = json.dumps({"error": str(exc)})

                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result,
                    }
                )

        # Max iterations reached — get a final response without tools
        log.warning("tool_loop_max_iterations", max_iterations=max_iterations)
        response = self._call_litellm(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return response.choices[0].message.content or ""

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
