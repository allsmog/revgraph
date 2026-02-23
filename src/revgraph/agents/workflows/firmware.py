"""Firmware ecosystem analysis workflow."""

from __future__ import annotations

from revgraph.agents.base import BaseWorkflow

_SYSTEM_PROMPT = (
    "You are a firmware security analyst. Your task is to analyze a firmware "
    "ecosystem by examining all loaded binaries, their shared libraries, "
    "cross-binary dependencies, and shared functions.\n\n"
    "Use the provided tools to:\n"
    "1. List all loaded binaries (query_graph)\n"
    "2. Examine each binary's imports and functions\n"
    "3. Identify shared dependencies between binaries\n"
    "4. Assess supply chain risks\n\n"
    "Produce a report covering: architecture overview, shared dependencies, "
    "potential supply chain risks, and hardening recommendations."
)

_TOOLS = [
    "load_binary_info",
    "query_graph",
    "list_functions",
    "get_function_details",
    "get_function_imports",
    "search_functions",
    "search_strings",
    "compute_bbr",
    "get_dangerous_functions",
]


class FirmwareWorkflow(BaseWorkflow):
    name = "firmware"
    description = "Firmware ecosystem analysis"
    agents = ["FirmwareScanner", "DependencyMapper", "EcosystemReporter"]

    async def run(
        self, input_text: str, max_turns: int = 30, interactive: bool = False
    ) -> str:
        """Analyze firmware ecosystem via agentic tool loop."""
        return self._run_agent(
            system_prompt=_SYSTEM_PROMPT,
            user_msg=input_text,
            tool_names=_TOOLS,
            max_iterations=max_turns,
        )
