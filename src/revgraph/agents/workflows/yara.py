"""YARA rule generation and validation workflow."""

from __future__ import annotations

from revgraph.agents.base import BaseWorkflow


class YARAWorkflow(BaseWorkflow):
    name = "yara"
    description = "Generate and validate YARA rules"
    agents = ["BinaryAnalyst", "YARAWriter", "YARAValidator"]

    async def run(
        self, input_text: str, max_turns: int = 30, interactive: bool = False
    ) -> str:
        """Generate and validate YARA rules for a binary."""
        from revgraph.llm.yara_generator import YARAGenerator

        # Extract SHA256
        sha256 = input_text.strip().split()[0] if input_text.strip() else ""
        if len(sha256) != 64:
            from revgraph.graph.query_engine import QueryEngine

            engine = QueryEngine(self._driver)
            binaries = engine.execute("MATCH (b:BinaryFile) RETURN b.sha256 AS sha256 LIMIT 1")
            if binaries:
                sha256 = binaries[0]["sha256"]
            else:
                return "No binaries found. Load a binary first."

        # Step 1: Generate rules
        generator = YARAGenerator(self._llm, self._driver)
        rules = generator.generate(sha256)

        # Step 2: Validate with LLM
        validation = self._llm.complete(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a YARA rule validator. Check these rules for:\n"
                        "1. Syntax correctness\n"
                        "2. Overly broad conditions that cause false positives\n"
                        "3. Missing meta fields\n"
                        "4. Effectiveness of string patterns\n"
                        "Provide the corrected rules if any issues are found."
                    ),
                },
                {"role": "user", "content": f"Validate these YARA rules:\n\n{rules}"},
            ],
        )

        return f"--- Generated YARA Rules ---\n\n{rules}\n\n--- Validation ---\n\n{validation}"
