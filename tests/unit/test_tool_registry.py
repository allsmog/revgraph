"""Tests for ToolRegistry — new tools, bridge, and schema filtering."""

import json
from unittest.mock import MagicMock

from revgraph.agents.registry import ToolDefinition, ToolRegistry
from revgraph.config.models import LLMConfig
from revgraph.llm.client import LLMClient


def _make_registry() -> ToolRegistry:
    """Build a registry with a mock Neo4j driver."""
    driver = MagicMock()
    config = LLMConfig(default_provider="openai", default_model="gpt-4o")
    llm = LLMClient(config)
    return ToolRegistry(driver, llm)


# ---------------------------------------------------------------------------
# Registration checks
# ---------------------------------------------------------------------------

EXPECTED_GRANULAR_TOOLS = [
    "get_function_details",
    "get_function_strings",
    "get_function_imports",
    "list_functions",
    "get_basic_blocks",
    "get_instructions",
    "search_strings",
    "search_functions",
    "get_function_callers",
    "get_function_callees",
]


def test_all_granular_tools_registered():
    """All 8 new granular tools (plus callers/callees) are registered."""
    registry = _make_registry()
    names = {t.name for t in registry.list_tools()}
    for tool_name in EXPECTED_GRANULAR_TOOLS:
        assert tool_name in names, f"{tool_name} not registered"


def test_existing_tools_still_registered():
    """Pre-existing high-level tools are still present."""
    registry = _make_registry()
    names = {t.name for t in registry.list_tools()}
    for tool_name in ["load_binary_info", "query_graph", "compute_bbr", "get_dangerous_functions"]:
        assert tool_name in names


# ---------------------------------------------------------------------------
# get_tool_schemas_by_name
# ---------------------------------------------------------------------------

def test_get_tool_schemas_by_name_filters():
    """Only requested tools appear in the schema list."""
    registry = _make_registry()
    subset = ["get_function_details", "search_strings"]
    schemas = registry.get_tool_schemas_by_name(subset)

    assert len(schemas) == 2
    schema_names = {s["function"]["name"] for s in schemas}
    assert schema_names == {"get_function_details", "search_strings"}


def test_get_tool_schemas_by_name_ignores_unknown():
    """Unknown tool names are silently skipped."""
    registry = _make_registry()
    schemas = registry.get_tool_schemas_by_name(["get_function_details", "nonexistent_tool"])
    assert len(schemas) == 1


def test_get_tool_schemas_by_name_empty():
    """Empty name list returns empty schema list."""
    registry = _make_registry()
    assert registry.get_tool_schemas_by_name([]) == []


# ---------------------------------------------------------------------------
# make_tool_executor
# ---------------------------------------------------------------------------

def test_make_tool_executor_returns_json():
    """Executor returns a JSON string."""
    registry = _make_registry()
    # Register a simple test tool
    registry.register(ToolDefinition(
        name="test_tool",
        description="A test tool",
        func=lambda x: {"result": x},
        parameters={"type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"]},
    ))

    executor = registry.make_tool_executor()
    result = executor("test_tool", {"x": "hello"})

    parsed = json.loads(result)
    assert parsed == {"result": "hello"}


def test_make_tool_executor_unknown_tool():
    """Executor returns error JSON for unknown tools."""
    registry = _make_registry()
    executor = registry.make_tool_executor()
    result = executor("does_not_exist", {})

    parsed = json.loads(result)
    assert "error" in parsed
    assert "does_not_exist" in parsed["error"]


def test_make_tool_executor_serializes_non_json():
    """Executor uses default=str for non-serializable values."""
    registry = _make_registry()
    registry.register(ToolDefinition(
        name="addr_tool",
        description="Returns an address",
        func=lambda: {"address": 0x401000},
    ))

    executor = registry.make_tool_executor()
    result = executor("addr_tool", {})
    parsed = json.loads(result)
    assert parsed["address"] == 4198400


# ---------------------------------------------------------------------------
# Schema structure
# ---------------------------------------------------------------------------

def test_tool_schemas_have_correct_structure():
    """Each schema has type=function, function.name, function.parameters."""
    registry = _make_registry()
    schemas = registry.get_tool_schemas()

    for schema in schemas:
        assert schema["type"] == "function"
        assert "name" in schema["function"]
        assert "description" in schema["function"]
        assert "parameters" in schema["function"]
        params = schema["function"]["parameters"]
        assert params.get("type") == "object"
