"""Binary summarization workflow."""

from __future__ import annotations

from revgraph.agents.base import BaseWorkflow


class SummarizeWorkflow(BaseWorkflow):
    name = "summarize"
    description = "Summarize all functions in a binary"
    agents = ["Summarizer", "Reporter"]

    async def run(
        self, input_text: str, max_turns: int = 30, interactive: bool = False
    ) -> str:
        """Summarize functions in a binary, prioritized by BBR."""
        from revgraph.llm.summarizer import Summarizer
        from revgraph.analysis.bbr import get_top_bbr_functions

        sha256 = input_text.strip().split()[0] if input_text.strip() else ""
        if len(sha256) != 64:
            from revgraph.graph.query_engine import QueryEngine

            engine = QueryEngine(self._driver)
            binaries = engine.execute("MATCH (b:BinaryFile) RETURN b.sha256 AS sha256 LIMIT 1")
            if binaries:
                sha256 = binaries[0]["sha256"]
            else:
                return "No binaries found. Load a binary first."

        summarizer = Summarizer(self._llm, self._driver)

        # Get top functions by BBR
        top_funcs = get_top_bbr_functions(self._driver, sha256, limit=20)
        if not top_funcs:
            # Fall back to first 20 functions
            from revgraph.graph.query_engine import QueryEngine

            engine = QueryEngine(self._driver)
            top_funcs = engine.execute(
                "MATCH (f:Function {binary_sha256: $sha256}) "
                "RETURN f.name AS name, f.address AS address LIMIT 20",
                params={"sha256": sha256},
            )

        summaries = []
        for func in top_funcs:
            result = summarizer.summarize(str(func["address"]), scope="function")
            if not result.get("error"):
                summaries.append(
                    f"### {func['name']} ({hex(func['address'])})\n{result['summary']}\n"
                )
                # Write to graph
                summarizer.write_summary(str(func["address"]), result["summary"])

        # Generate binary-level summary
        binary_summary = summarizer.summarize(sha256, scope="binary")

        output = f"# Binary Summary\n\n{binary_summary.get('summary', '')}\n\n"
        output += f"# Function Summaries ({len(summaries)} functions)\n\n"
        output += "\n".join(summaries)

        return output
