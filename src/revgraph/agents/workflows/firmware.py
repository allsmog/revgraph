"""Firmware ecosystem analysis workflow."""

from __future__ import annotations

from revgraph.agents.base import BaseWorkflow


class FirmwareWorkflow(BaseWorkflow):
    name = "firmware"
    description = "Firmware ecosystem analysis"
    agents = ["FirmwareScanner", "DependencyMapper", "EcosystemReporter"]

    async def run(
        self, input_text: str, max_turns: int = 30, interactive: bool = False
    ) -> str:
        """Analyze firmware ecosystem — shared libraries, dependencies, etc."""
        from revgraph.graph.query_engine import QueryEngine
        from revgraph.graph.cross_binary import find_shared_imports, find_shared_functions

        engine = QueryEngine(self._driver)

        # Step 1: List all loaded binaries
        binaries = engine.execute(
            "MATCH (b:BinaryFile) "
            "OPTIONAL MATCH (b)-[:DEFINES]->(f:Function) "
            "RETURN b.name AS name, b.sha256 AS sha256, "
            "b.architecture AS arch, count(f) AS num_functions "
            "ORDER BY b.name"
        )

        if len(binaries) < 2:
            return "Firmware analysis requires at least 2 loaded binaries."

        # Step 2: Cross-binary dependency analysis
        dependency_map = []
        sha_list = [b["sha256"] for b in binaries]

        for i in range(len(sha_list)):
            for j in range(i + 1, len(sha_list)):
                shared = find_shared_imports(self._driver, sha_list[i], sha_list[j])
                shared_funcs = find_shared_functions(self._driver, sha_list[i], sha_list[j])
                if shared or shared_funcs:
                    dependency_map.append(
                        {
                            "binary_a": binaries[i]["name"],
                            "binary_b": binaries[j]["name"],
                            "shared_imports": len(shared),
                            "shared_functions": len(shared_funcs),
                        }
                    )

        # Step 3: Generate ecosystem report
        report_data = f"Firmware Ecosystem: {len(binaries)} binaries\n\n"
        for b in binaries:
            report_data += f"  - {b['name']} ({b['arch']}): {b['num_functions']} functions\n"

        report_data += f"\nDependencies ({len(dependency_map)} pairs):\n"
        for dep in dependency_map:
            report_data += (
                f"  {dep['binary_a']} <-> {dep['binary_b']}: "
                f"{dep['shared_imports']} shared imports, "
                f"{dep['shared_functions']} shared functions\n"
            )

        report = self._llm.complete(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a firmware security analyst. Analyze the firmware ecosystem "
                        "and produce a report covering: architecture overview, shared dependencies, "
                        "potential supply chain risks, and hardening recommendations."
                    ),
                },
                {"role": "user", "content": report_data + "\n\n" + input_text},
            ],
            max_tokens=4096,
        )

        return report
