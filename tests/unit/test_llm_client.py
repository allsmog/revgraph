"""Tests for the LLM client wrapper."""

import json
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


# ---------------------------------------------------------------------------
# tool_loop tests
# ---------------------------------------------------------------------------

def _make_client() -> LLMClient:
    config = LLMConfig(default_provider="openai", default_model="gpt-4o")
    return LLMClient(config)


def _mock_response(content: str, tool_calls=None, usage_tokens=15):
    """Build a mock litellm response."""
    resp = MagicMock()
    msg = MagicMock()
    msg.content = content
    msg.tool_calls = tool_calls
    msg.model_dump.return_value = {
        "role": "assistant",
        "content": content,
        "tool_calls": [
            {
                "id": tc.id,
                "type": "function",
                "function": {"name": tc.function.name, "arguments": tc.function.arguments},
            }
            for tc in (tool_calls or [])
        ] if tool_calls else None,
    }
    resp.choices = [MagicMock()]
    resp.choices[0].message = msg
    resp.usage.prompt_tokens = usage_tokens // 3
    resp.usage.completion_tokens = usage_tokens - usage_tokens // 3
    resp.usage.total_tokens = usage_tokens
    return resp


def _mock_tool_call(tc_id: str, name: str, args: dict):
    tc = MagicMock()
    tc.id = tc_id
    tc.function.name = name
    tc.function.arguments = json.dumps(args)
    return tc


@patch("litellm.completion")
def test_tool_loop_no_tool_calls(mock_completion):
    """When the model returns no tool calls, return text directly."""
    mock_completion.return_value = _mock_response("Final answer")

    client = _make_client()
    result = client.tool_loop(
        messages=[{"role": "user", "content": "hello"}],
        tools=[],
        tool_executor=lambda name, args: "unused",
    )

    assert result == "Final answer"
    assert mock_completion.call_count == 1


@patch("litellm.completion")
def test_tool_loop_single_tool_call(mock_completion):
    """Single tool call → executor called → result fed back → final text."""
    tc = _mock_tool_call("tc_1", "get_info", {"key": "val"})
    call_with_tool = _mock_response("", tool_calls=[tc])
    final_response = _mock_response("Got info: hello")

    mock_completion.side_effect = [call_with_tool, final_response]

    executor_calls = []

    def executor(name, args):
        executor_calls.append((name, args))
        return json.dumps({"data": "hello"})

    client = _make_client()
    result = client.tool_loop(
        messages=[{"role": "user", "content": "get info"}],
        tools=[{"type": "function", "function": {"name": "get_info"}}],
        tool_executor=executor,
    )

    assert result == "Got info: hello"
    assert len(executor_calls) == 1
    assert executor_calls[0] == ("get_info", {"key": "val"})
    assert mock_completion.call_count == 2


@patch("litellm.completion")
def test_tool_loop_multiple_iterations(mock_completion):
    """Multiple tool iterations accumulate messages correctly."""
    tc1 = _mock_tool_call("tc_1", "step1", {})
    tc2 = _mock_tool_call("tc_2", "step2", {"from": "step1"})

    resp1 = _mock_response("", tool_calls=[tc1])
    resp2 = _mock_response("", tool_calls=[tc2])
    resp3 = _mock_response("Done after two tool rounds")

    mock_completion.side_effect = [resp1, resp2, resp3]

    calls = []

    def executor(name, args):
        calls.append(name)
        return json.dumps({"ok": True})

    client = _make_client()
    result = client.tool_loop(
        messages=[{"role": "user", "content": "multi step"}],
        tools=[{"type": "function", "function": {"name": "step1"}},
               {"type": "function", "function": {"name": "step2"}}],
        tool_executor=executor,
    )

    assert result == "Done after two tool rounds"
    assert calls == ["step1", "step2"]
    assert mock_completion.call_count == 3


@patch("litellm.completion")
def test_tool_loop_max_iterations(mock_completion):
    """Loop terminates at max_iterations and makes a final call without tools."""
    tc = _mock_tool_call("tc_inf", "loop_forever", {})

    # Every call returns a tool call, forcing the loop to hit max
    tool_resp = _mock_response("", tool_calls=[tc])
    final_resp = _mock_response("Forced stop")

    # max_iterations=2, so 2 tool-call responses + 1 final
    mock_completion.side_effect = [tool_resp, tool_resp, final_resp]

    client = _make_client()
    result = client.tool_loop(
        messages=[{"role": "user", "content": "loop"}],
        tools=[{"type": "function", "function": {"name": "loop_forever"}}],
        tool_executor=lambda name, args: json.dumps({"continue": True}),
        max_iterations=2,
    )

    assert result == "Forced stop"
    # 2 iterations with tools + 1 final without tools
    assert mock_completion.call_count == 3


@patch("litellm.completion")
def test_tool_loop_executor_error(mock_completion):
    """Tool executor exception is serialized as tool result error."""
    tc = _mock_tool_call("tc_err", "broken_tool", {})
    tool_resp = _mock_response("", tool_calls=[tc])
    final_resp = _mock_response("Handled error gracefully")

    mock_completion.side_effect = [tool_resp, final_resp]

    def broken_executor(name, args):
        raise RuntimeError("tool crashed")

    client = _make_client()
    result = client.tool_loop(
        messages=[{"role": "user", "content": "try broken"}],
        tools=[{"type": "function", "function": {"name": "broken_tool"}}],
        tool_executor=broken_executor,
    )

    assert result == "Handled error gracefully"
    # Check the tool result message contains the error
    second_call_messages = mock_completion.call_args_list[1][1]["messages"]
    tool_result_msg = [m for m in second_call_messages if m.get("role") == "tool"]
    assert len(tool_result_msg) == 1
    assert "tool crashed" in tool_result_msg[0]["content"]


@patch("litellm.completion")
def test_tool_loop_tracks_token_usage(mock_completion):
    """Token usage accumulates across all iterations."""
    tc = _mock_tool_call("tc_1", "tool", {})
    resp1 = _mock_response("", tool_calls=[tc], usage_tokens=30)
    resp2 = _mock_response("done", usage_tokens=20)

    mock_completion.side_effect = [resp1, resp2]

    client = _make_client()
    client.tool_loop(
        messages=[{"role": "user", "content": "go"}],
        tools=[{"type": "function", "function": {"name": "tool"}}],
        tool_executor=lambda name, args: "{}",
    )

    assert client.usage.total_tokens == 50
