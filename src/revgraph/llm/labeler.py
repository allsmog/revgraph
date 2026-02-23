"""Function labeling — suggest descriptive names using LLM."""

from __future__ import annotations

import json
from typing import Any

from neo4j import Driver

from revgraph.agents.registry import ToolRegistry
from revgraph.llm.client import LLMClient
from revgraph.llm.prompts import AGENT_LABEL_FUNCTION
from revgraph.utils.logging import get_logger

log = get_logger(__name__)

_LABEL_TOOLS = [
    "get_function_details",
    "get_function_strings",
    "get_function_imports",
    "get_function_callers",
    "get_function_callees",
]


class FunctionLabeler:
    """Label functions with descriptive names using LLM analysis."""

    def __init__(
        self, llm: LLMClient, driver: Driver, registry: ToolRegistry | None = None,
    ) -> None:
        self._llm = llm
        self._driver = driver
        self._registry = registry or ToolRegistry(driver, llm)

    def label_functions(
        self,
        sha256: str,
        confidence_threshold: float = 0.7,
    ) -> list[dict[str, Any]]:
        """Label all unlabeled functions in a binary."""
        functions = self._get_unlabeled_functions(sha256)
        results = []

        tools = self._registry.get_tool_schemas_by_name(_LABEL_TOOLS)
        executor = self._registry.make_tool_executor()

        for func in functions:
            label_result = self._label_single(func, sha256, tools, executor)
            if label_result and label_result.get("confidence", 0) >= confidence_threshold:
                results.append(
                    {
                        "address": func["address"],
                        "original_name": func["name"],
                        "label": label_result["label"],
                        "confidence": label_result["confidence"],
                        "reasoning": label_result.get("reasoning", ""),
                    }
                )

        log.info(
            "functions_labeled",
            sha256=sha256[:12],
            labeled=len(results),
            total=len(functions),
        )
        return results

    def _label_single(
        self,
        func: dict[str, Any],
        sha256: str,
        tools: list[dict[str, Any]],
        executor: Any,
    ) -> dict[str, Any] | None:
        """Label a single function via agentic tool loop."""
        address = hex(func["address"]) if isinstance(func["address"], int) else func["address"]

        messages = [
            {"role": "system", "content": AGENT_LABEL_FUNCTION},
            {
                "role": "user",
                "content": (
                    f"Suggest a descriptive name for the function '{func['name']}' "
                    f"at address {address} in binary {sha256}."
                ),
            },
        ]

        raw = self._llm.tool_loop(
            messages=messages,
            tools=tools,
            tool_executor=executor,
            temperature=0.1,
            max_iterations=6,
        )

        try:
            raw = raw.strip()
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[1].rsplit("```", 1)[0]
            return json.loads(raw)
        except json.JSONDecodeError:
            log.warning("label_parse_failed", function=func["name"])
            return None

    def write_labels(
        self, sha256: str, labels: list[dict[str, Any]]
    ) -> None:
        """Write labels to Function nodes in Neo4j."""
        rows = [
            {"address": entry["address"], "label": entry["label"]}
            for entry in labels
        ]

        with self._driver.session() as session:
            session.run(
                "UNWIND $rows AS r "
                "MATCH (f:Function {address: r.address, binary_sha256: $sha256}) "
                "SET f.label = r.label",
                rows=rows,
                sha256=sha256,
            )

        log.info("labels_written", sha256=sha256[:12], count=len(rows))

    def _get_unlabeled_functions(
        self, sha256: str
    ) -> list[dict[str, Any]]:
        """Get functions that need labeling (address + name only)."""
        with self._driver.session() as session:
            result = session.run(
                "MATCH (f:Function {binary_sha256: $sha256}) "
                "WHERE f.label IS NULL AND "
                "(f.name STARTS WITH 'FUN_' OR f.name STARTS WITH 'sub_' "
                "OR f.name STARTS WITH 'fcn.') "
                "RETURN f.name AS name, f.address AS address",
                sha256=sha256,
            )
            return [dict(r) for r in result]
