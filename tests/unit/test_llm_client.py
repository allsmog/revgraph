"""Tests for the LLM client wrapper."""

import os
from unittest.mock import MagicMock, patch

from revgraph.config.models import LLMConfig
from revgraph.llm.client import LLMClient, TokenUsage


def test_token_usage_tracking():
    usage = TokenUsage()
    usage.update({"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150})
    assert usage.prompt_tokens == 100
    assert usage.completion_tokens == 50
    assert usage.total_tokens == 150

    usage.update({"prompt_tokens": 200, "completion_tokens": 100, "total_tokens": 300})
    assert usage.total_tokens == 450


def test_default_model():
    config = LLMConfig(default_model="gpt-4o")
    client = LLMClient(config)
    assert client.default_model == "gpt-4o"


@patch("litellm.completion")
def test_complete(mock_completion):
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "test response"
    mock_response.usage.prompt_tokens = 10
    mock_response.usage.completion_tokens = 5
    mock_response.usage.total_tokens = 15
    mock_completion.return_value = mock_response

    config = LLMConfig(default_provider="openai", default_model="gpt-3.5-turbo", temperature=0.0)
    client = LLMClient(config)
    result = client.complete(messages=[{"role": "user", "content": "hello"}])

    assert result == "test response"
    assert client.usage.total_tokens == 15
    mock_completion.assert_called_once()


@patch("litellm.embedding")
def test_embed(mock_embedding):
    mock_response = MagicMock()
    mock_response.data = [
        {"embedding": [0.1, 0.2, 0.3]},
        {"embedding": [0.4, 0.5, 0.6]},
    ]
    mock_embedding.return_value = mock_response

    config = LLMConfig()
    client = LLMClient(config)
    result = client.embed(["text1", "text2"])

    assert len(result) == 2
    assert result[0] == [0.1, 0.2, 0.3]


@patch("litellm.completion")
def test_complete_uses_model_override(mock_completion):
    """Model kwarg should override the config default."""
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "ok"
    mock_response.usage.prompt_tokens = 1
    mock_response.usage.completion_tokens = 1
    mock_response.usage.total_tokens = 2
    mock_completion.return_value = mock_response

    config = LLMConfig(default_provider="openai", default_model="gpt-4o")
    client = LLMClient(config)
    client.complete(messages=[{"role": "user", "content": "hi"}], model="gpt-3.5-turbo")

    call_kwargs = mock_completion.call_args
    assert call_kwargs[1]["model"] == "gpt-3.5-turbo"


@patch("litellm.completion")
def test_complete_uses_default_model(mock_completion):
    """When no model kwarg, config default_model is used."""
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "ok"
    mock_response.usage.prompt_tokens = 1
    mock_response.usage.completion_tokens = 1
    mock_response.usage.total_tokens = 2
    mock_completion.return_value = mock_response

    config = LLMConfig(default_provider="openai", default_model="gpt-4o")
    client = LLMClient(config)
    client.complete(messages=[{"role": "user", "content": "hi"}])

    call_kwargs = mock_completion.call_args
    assert call_kwargs[1]["model"] == "gpt-4o"


def test_api_key_preserves_existing_env():
    """Existing env vars should not be overwritten by config api_keys."""
    original = os.environ.get("ANTHROPIC_API_KEY")
    os.environ["ANTHROPIC_API_KEY"] = "existing-key"
    try:
        config = LLMConfig(api_keys={"anthropic": "config-key"})
        LLMClient(config)
        assert os.environ["ANTHROPIC_API_KEY"] == "existing-key"
    finally:
        if original is None:
            os.environ.pop("ANTHROPIC_API_KEY", None)
        else:
            os.environ["ANTHROPIC_API_KEY"] = original
