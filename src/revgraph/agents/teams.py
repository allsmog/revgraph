"""AgentTeamFactory — create tool-loop team compositions for workflows."""

from __future__ import annotations

from typing import Any

from neo4j import Driver

from revgraph.agents.registry import ToolRegistry
from revgraph.config.models import RevGraphConfig
from revgraph.llm.client import LLMClient
from revgraph.utils.logging import get_logger

log = get_logger(__name__)

WORKFLOW_REGISTRY: dict[str, dict[str, Any]] = {
    "analysis": {
        "description": "Full binary analysis workflow",
        "agents": ["Extractor", "GraphAnalyst", "EmbeddingSpecialist", "SecurityAnalyst", "Reporter"],
    },
    "patch-impact": {
        "description": "Assess patch propagation through call graph",
        "agents": ["PatchAnalyst", "ImpactAssessor", "Reporter"],
    },
    "nday-triage": {
        "description": "Prioritize potential N-day vulnerabilities",
        "agents": ["VulnHunter", "BBRAnalyst", "TriageReporter"],
    },
    "yara": {
        "description": "Generate and validate YARA rules",
        "agents": ["BinaryAnalyst", "YARAWriter", "YARAValidator"],
    },
    "firmware": {
        "description": "Firmware ecosystem analysis",
        "agents": ["FirmwareScanner", "DependencyMapper", "EcosystemReporter"],
    },
    "summarize": {
        "description": "Summarize all functions in a binary",
        "agents": ["Summarizer", "Reporter"],
    },
}

AGENT_PROMPTS: dict[str, str] = {
    "Extractor": (
        "You are a binary extraction specialist. Your role is to load and examine "
        "binary artifacts, listing functions, imports, and strings."
    ),
    "GraphAnalyst": (
        "You are a graph analysis expert. You query the Neo4j graph to analyze "
        "call graphs, control flow, and relationships between functions."
    ),
    "EmbeddingSpecialist": (
        "You are an embedding and similarity expert. You generate embeddings, "
        "find similar functions, and identify code reuse patterns."
    ),
    "SecurityAnalyst": (
        "You are a security analyst. You identify dangerous API usage, "
        "trace vulnerability paths, and assess security posture."
    ),
    "Reporter": (
        "You are a technical report writer. You compile findings from other "
        "agents into clear, actionable reports."
    ),
    "PatchAnalyst": (
        "You analyze code patches to identify what changed between binary versions."
    ),
    "ImpactAssessor": (
        "You assess the impact of changes by tracing callers and dependencies."
    ),
    "VulnHunter": (
        "You hunt for vulnerabilities by examining dangerous API usage and "
        "decompiled code patterns."
    ),
    "BBRAnalyst": (
        "You use Basic Block Rank scores to prioritize which code areas "
        "are most critical for security analysis."
    ),
    "TriageReporter": (
        "You create prioritized vulnerability triage reports."
    ),
    "BinaryAnalyst": (
        "You analyze binary characteristics including strings, imports, "
        "and opcode patterns for detection signature creation."
    ),
    "YARAWriter": (
        "You write YARA detection rules based on binary analysis findings."
    ),
    "YARAValidator": (
        "You validate YARA rules for correctness and detection effectiveness."
    ),
    "FirmwareScanner": (
        "You scan firmware images for embedded binaries and shared libraries."
    ),
    "DependencyMapper": (
        "You map dependencies between components in firmware ecosystems."
    ),
    "EcosystemReporter": (
        "You create reports on firmware ecosystem composition and risks."
    ),
    "Summarizer": (
        "You summarize binary functions using decompiled code and context."
    ),
}


class _SimpleTeam:
    """Agent team that uses a single tool-calling loop with combined prompts."""

    def __init__(
        self,
        config: RevGraphConfig,
        driver: Driver,
        llm: LLMClient,
        registry: ToolRegistry,
        workflow_name: str,
    ) -> None:
        self._config = config
        self._driver = driver
        self._llm = llm
        self._registry = registry
        self._workflow_name = workflow_name
        self._agents = WORKFLOW_REGISTRY[workflow_name]["agents"]

    async def run(
        self, input_text: str, max_turns: int = 30, interactive: bool = False
    ) -> str:
        """Run the workflow using a single-agent tool loop with combined system prompt."""
        # Build a combined system prompt from all agent roles
        role_descriptions = []
        for agent_name in self._agents:
            prompt = AGENT_PROMPTS.get(agent_name, f"You are {agent_name}.")
            role_descriptions.append(f"**{agent_name}**: {prompt}")

        system_prompt = (
            f"You are a multi-capability agent for the '{self._workflow_name}' workflow. "
            f"You combine the following expert roles:\n\n"
            + "\n".join(role_descriptions)
            + "\n\nUse the provided tools to explore the binary graph and "
            "produce a comprehensive result."
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": input_text},
        ]

        tools = self._registry.get_tool_schemas()
        executor = self._registry.make_tool_executor()

        return self._llm.tool_loop(
            messages=messages,
            tools=tools,
            tool_executor=executor,
            max_iterations=max_turns,
        )


class AgentTeamFactory:
    """Create agent teams for different workflows."""

    def __init__(
        self,
        config: RevGraphConfig,
        driver: Driver,
        llm: LLMClient,
    ) -> None:
        self._config = config
        self._driver = driver
        self._llm = llm
        self._registry = ToolRegistry(driver, llm)

    def create_team(self, workflow: str) -> _SimpleTeam:
        if workflow not in WORKFLOW_REGISTRY:
            available = ", ".join(WORKFLOW_REGISTRY.keys())
            raise ValueError(f"Unknown workflow '{workflow}'. Available: {available}")

        return _SimpleTeam(
            self._config,
            self._driver,
            self._llm,
            self._registry,
            workflow,
        )
