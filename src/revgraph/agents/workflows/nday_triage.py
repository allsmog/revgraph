"""N-day vulnerability triage workflow."""

from __future__ import annotations

from revgraph.agents.base import BaseWorkflow


class NdayTriageWorkflow(BaseWorkflow):
    name = "nday-triage"
    description = "Prioritize potential N-day vulnerabilities"
    agents = ["VulnHunter", "BBRAnalyst", "TriageReporter"]

    async def run(
        self, input_text: str, max_turns: int = 30, interactive: bool = False
    ) -> str:
        """Triage N-day vulnerabilities in a binary."""
        from revgraph.analysis.vulnerability import vulnerability_surface
        from revgraph.analysis.bbr import get_top_bbr_functions

        # Extract SHA256 from input
        sha256 = input_text.strip().split()[0] if input_text.strip() else ""
        if len(sha256) != 64:
            # Try to find it
            from revgraph.graph.query_engine import QueryEngine

            engine = QueryEngine(self._driver)
            binaries = engine.execute("MATCH (b:BinaryFile) RETURN b.sha256 AS sha256 LIMIT 1")
            if binaries:
                sha256 = binaries[0]["sha256"]
            else:
                return "No binaries found in graph. Load a binary first."

        # Step 1: Vulnerability surface analysis
        surface = vulnerability_surface(self._driver, sha256)

        # Step 2: BBR ranking
        top_funcs = get_top_bbr_functions(self._driver, sha256, limit=20)

        # Step 3: Combine and triage
        triage_data = (
            f"Binary: {sha256[:12]}...\n"
            f"Total dangerous functions: {surface['total_dangerous_functions']}\n"
            f"API usage: {surface['api_usage']}\n\n"
            f"High-risk functions (dangerous + high BBR):\n"
        )
        for func in surface.get("high_risk_functions", [])[:10]:
            triage_data += (
                f"  - {func['function_name']} @ {hex(func['address'])}: "
                f"APIs={func['dangerous_imports']}, BBR={func.get('max_bbr', 'N/A')}\n"
            )

        triage_data += f"\nTop BBR functions:\n"
        for func in top_funcs[:10]:
            triage_data += f"  - {func['name']} @ {hex(func['address'])}: BBR={func['max_bbr']:.6f}\n"

        # Step 4: LLM triage report
        report = self._llm.complete(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an N-day vulnerability triage specialist. "
                        "Analyze the findings and produce a prioritized triage report with: "
                        "1. Critical findings (immediate attention) "
                        "2. High-priority findings "
                        "3. Medium-priority findings "
                        "4. Recommendations"
                    ),
                },
                {"role": "user", "content": triage_data},
            ],
            max_tokens=4096,
        )

        return report
