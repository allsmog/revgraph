"""YARA rule generation and validation workflow."""

from __future__ import annotations

from revgraph.agents.base import BaseWorkflow

_SYSTEM_PROMPT = (
    "You are a malware analyst and YARA rule specialist. Your task is to "
    "generate and validate YARA rules for detecting a binary.\n\n"
    "Use the provided tools to:\n"
    "1. Load binary info\n"
    "2. Search for distinctive strings\n"
    "3. Examine imports and function patterns\n"
    "4. Look at opcode sequences in high-BBR basic blocks\n\n"
    "Generate well-structured YARA rules with:\n"
    "- Descriptive rule names\n"
    "- Appropriate meta fields\n"
    "- String and byte pattern conditions\n"
    "- Comments explaining each rule\n\n"
    "Then validate the rules for:\n"
    "1. Syntax correctness\n"
    "2. False positive risk (overly broad conditions)\n"
    "3. Missing meta fields\n"
    "4. Effectiveness of string patterns\n\n"
    "Output the final validated YARA rules."
)

_TOOLS = [
    "load_binary_info",
    "compute_bbr",
    "list_functions",
    "get_function_details",
    "get_function_imports",
    "get_basic_blocks",
    "get_instructions",
    "search_strings",
    "search_functions",
]


class YARAWorkflow(BaseWorkflow):
    name = "yara"
    description = "Generate and validate YARA rules"
    agents = ["BinaryAnalyst", "YARAWriter", "YARAValidator"]

    async def run(
        self, input_text: str, max_turns: int = 30, interactive: bool = False
    ) -> str:
        """Generate and validate YARA rules via agentic tool loop."""
        return self._run_agent(
            system_prompt=_SYSTEM_PROMPT,
            user_msg=input_text,
            tool_names=_TOOLS,
            max_iterations=max_turns,
        )
