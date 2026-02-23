"""Patch impact assessment workflow."""

from __future__ import annotations

from revgraph.agents.base import BaseWorkflow

_SYSTEM_PROMPT = (
    "You are a patch impact analyst. Your task is to compare two binary "
    "versions and assess the impact of changes.\n\n"
    "Use the provided tools to:\n"
    "1. Load binary info for both versions\n"
    "2. List and compare functions between versions\n"
    "3. Examine changed functions in detail\n"
    "4. Trace callers of changed functions to assess impact propagation\n\n"
    "Produce a patch impact report covering:\n"
    "- Functions added, removed, or modified\n"
    "- Call graph impact (which callers are affected)\n"
    "- Security implications of changes\n"
    "- Risk assessment"
)

_TOOLS = [
    "load_binary_info",
    "list_functions",
    "get_function_details",
    "get_function_callers",
    "get_function_callees",
    "get_function_imports",
    "search_functions",
    "query_graph",
]


class PatchImpactWorkflow(BaseWorkflow):
    name = "patch-impact"
    description = "Assess patch propagation through call graph"
    agents = ["PatchAnalyst", "ImpactAssessor", "Reporter"]

    async def run(
        self, input_text: str, max_turns: int = 30, interactive: bool = False
    ) -> str:
        """Analyze patch impact via agentic tool loop."""
        return self._run_agent(
            system_prompt=_SYSTEM_PROMPT,
            user_msg=input_text,
            tool_names=_TOOLS,
            max_iterations=max_turns,
        )
