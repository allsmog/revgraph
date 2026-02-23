"""N-day vulnerability triage workflow."""

from __future__ import annotations

from revgraph.agents.base import BaseWorkflow

_SYSTEM_PROMPT = (
    "You are an N-day vulnerability triage specialist. Your task is to "
    "analyze a binary for potential N-day vulnerabilities and produce a "
    "prioritized triage report.\n\n"
    "Use the provided tools to:\n"
    "1. Load binary info and compute BBR scores\n"
    "2. Find dangerous functions (dangerous API usage)\n"
    "3. Examine high-BBR functions for vulnerability patterns\n"
    "4. Inspect decompiled code of suspicious functions\n\n"
    "Produce a prioritized triage report with:\n"
    "1. Critical findings (immediate attention)\n"
    "2. High-priority findings\n"
    "3. Medium-priority findings\n"
    "4. Recommendations"
)

_TOOLS = [
    "load_binary_info",
    "compute_bbr",
    "get_dangerous_functions",
    "list_functions",
    "get_function_details",
    "get_function_strings",
    "get_function_imports",
    "get_function_callers",
    "get_function_callees",
    "search_strings",
    "search_functions",
]


class NdayTriageWorkflow(BaseWorkflow):
    name = "nday-triage"
    description = "Prioritize potential N-day vulnerabilities"
    agents = ["VulnHunter", "BBRAnalyst", "TriageReporter"]

    async def run(
        self, input_text: str, max_turns: int = 30, interactive: bool = False
    ) -> str:
        """Triage N-day vulnerabilities via agentic tool loop."""
        return self._run_agent(
            system_prompt=_SYSTEM_PROMPT,
            user_msg=input_text,
            tool_names=_TOOLS,
            max_iterations=max_turns,
        )
