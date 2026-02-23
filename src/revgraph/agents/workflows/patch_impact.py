"""Patch impact assessment workflow."""

from __future__ import annotations

from revgraph.agents.base import BaseWorkflow


class PatchImpactWorkflow(BaseWorkflow):
    name = "patch-impact"
    description = "Assess patch propagation through call graph"
    agents = ["PatchAnalyst", "ImpactAssessor", "Reporter"]

    async def run(
        self, input_text: str, max_turns: int = 30, interactive: bool = False
    ) -> str:
        """Analyze patch impact by comparing two binaries.

        Expected input: "sha256_old sha256_new" or description of patch.
        """
        parts = input_text.strip().split()

        if len(parts) >= 2 and len(parts[0]) == 64 and len(parts[1]) == 64:
            sha256_old, sha256_new = parts[0], parts[1]
        else:
            # Use LLM to interpret the input
            response = self._llm.complete(
                messages=[
                    {"role": "system", "content": "Extract two SHA256 hashes from the user input. Return only the hashes, space-separated."},
                    {"role": "user", "content": input_text},
                ],
            )
            hashes = response.strip().split()
            if len(hashes) < 2:
                return "Please provide two binary SHA256 hashes to compare."
            sha256_old, sha256_new = hashes[0], hashes[1]

        # Step 1: Diff functions
        from revgraph.graph.cross_binary import diff_functions

        diff = diff_functions(self._driver, sha256_old, sha256_new)

        # Step 2: Trace impact of changed functions
        impact = []
        for func in diff.get("size_changed", [])[:20]:
            from revgraph.agents.tools import get_function_callers

            callers = get_function_callers(
                self._driver, func["address"], sha256_new
            )
            impact.append(
                {
                    "function": func["name"],
                    "callers": [c["name"] for c in callers],
                    "size_change": func["size_b"] - func["size"],
                }
            )

        # Step 3: Generate report
        report_prompt = (
            f"Generate a patch impact report.\n\n"
            f"Functions only in old binary: {len(diff.get('only_in_a', []))}\n"
            f"Functions only in new binary: {len(diff.get('only_in_b', []))}\n"
            f"Functions with size changes: {len(diff.get('size_changed', []))}\n\n"
            f"Impact analysis:\n{impact}"
        )

        report = self._llm.complete(
            messages=[
                {"role": "system", "content": "You are a patch impact analyst."},
                {"role": "user", "content": report_prompt},
            ],
        )

        return report
