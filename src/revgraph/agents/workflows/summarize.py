"""Binary summarization workflow."""

from __future__ import annotations

from revgraph.agents.base import BaseWorkflow

_SYSTEM_PROMPT = (
    "You are a reverse engineering expert. Your task is to summarize all "
    "key functions in a binary and produce a comprehensive binary-level "
    "summary.\n\n"
    "Use the provided tools to:\n"
    "1. Load binary info\n"
    "2. Compute BBR scores to prioritize functions\n"
    "3. List functions (start with highest-BBR ones)\n"
    "4. For each key function, get its details, strings, and imports\n"
    "5. Produce individual function summaries and an overall binary summary\n\n"
    "Format your output as:\n"
    "# Binary Summary\n"
    "[overall summary]\n\n"
    "# Function Summaries\n"
    "### function_name (0xADDR)\n"
    "[summary]\n"
)

_TOOLS = [
    "load_binary_info",
    "compute_bbr",
    "list_functions",
    "get_function_details",
    "get_function_strings",
    "get_function_imports",
    "get_function_callers",
    "get_function_callees",
    "search_strings",
]


class SummarizeWorkflow(BaseWorkflow):
    name = "summarize"
    description = "Summarize all functions in a binary"
    agents = ["Summarizer", "Reporter"]

    async def run(
        self, input_text: str, max_turns: int = 30, interactive: bool = False
    ) -> str:
        """Summarize binary functions via agentic tool loop."""
        return self._run_agent(
            system_prompt=_SYSTEM_PROMPT,
            user_msg=input_text,
            tool_names=_TOOLS,
            max_iterations=max_turns,
        )
