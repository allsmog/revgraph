"""Few-shot example bank for NL2Cypher translation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FewShotExample:
    question: str
    cypher: str
    category: str = "general"


FEW_SHOT_BANK: list[FewShotExample] = [
    FewShotExample(
        question="List all binaries",
        cypher="MATCH (b:BinaryFile) RETURN b.name AS name, b.sha256 AS sha256 ORDER BY b.name",
        category="binary",
    ),
    FewShotExample(
        question="What functions call malloc?",
        cypher=(
            "MATCH (f:Function)-[:REFERENCES_IMPORT]->(i:Import {name: 'malloc'}) "
            "RETURN f.name AS function_name, f.address AS address, f.binary_sha256 AS binary"
        ),
        category="import",
    ),
    FewShotExample(
        question="Show the call graph for function at address 0x401000",
        cypher=(
            "MATCH (f:Function {address: 4198400})-[:CALLS]->(callee:Function) "
            "RETURN f.name AS caller, callee.name AS callee, callee.address AS callee_address"
        ),
        category="callgraph",
    ),
    FewShotExample(
        question="Find functions that reference the string 'password'",
        cypher=(
            "MATCH (f:Function)-[:REFERENCES_STRING]->(s:String) "
            "WHERE s.value CONTAINS 'password' "
            "RETURN f.name AS function_name, s.value AS string_value"
        ),
        category="string",
    ),
    FewShotExample(
        question="What are the top 10 most important basic blocks?",
        cypher=(
            "MATCH (bb:BasicBlock) WHERE bb.bbr_score IS NOT NULL "
            "RETURN bb.address AS address, bb.bbr_score AS score, bb.binary_sha256 AS binary "
            "ORDER BY bb.bbr_score DESC LIMIT 10"
        ),
        category="bbr",
    ),
    FewShotExample(
        question="Show functions that call both malloc and free",
        cypher=(
            "MATCH (f:Function)-[:REFERENCES_IMPORT]->(m:Import {name: 'malloc'}) "
            "MATCH (f)-[:REFERENCES_IMPORT]->(fr:Import {name: 'free'}) "
            "RETURN f.name AS function_name, f.address AS address"
        ),
        category="import",
    ),
    FewShotExample(
        question="Find functions with more than 50 basic blocks",
        cypher=(
            "MATCH (f:Function)-[:CONTAINS]->(bb:BasicBlock) "
            "WITH f, count(bb) AS block_count "
            "WHERE block_count > 50 "
            "RETURN f.name AS name, f.address AS address, block_count "
            "ORDER BY block_count DESC"
        ),
        category="complexity",
    ),
    FewShotExample(
        question="Which functions are called by the most other functions?",
        cypher=(
            "MATCH (caller:Function)-[:CALLS]->(f:Function) "
            "WITH f, count(caller) AS caller_count "
            "RETURN f.name AS name, f.address AS address, caller_count "
            "ORDER BY caller_count DESC LIMIT 20"
        ),
        category="callgraph",
    ),
    FewShotExample(
        question="Find functions that use dangerous APIs like strcpy, sprintf, gets",
        cypher=(
            "MATCH (f:Function)-[:REFERENCES_IMPORT]->(i:Import) "
            "WHERE i.name IN ['strcpy', 'sprintf', 'gets', 'strcat', 'scanf'] "
            "RETURN f.name AS function_name, collect(i.name) AS dangerous_apis, f.address AS address"
        ),
        category="vulnerability",
    ),
    FewShotExample(
        question="Show the control flow graph for function main",
        cypher=(
            "MATCH (f:Function {name: 'main'})-[:CONTAINS]->(bb:BasicBlock) "
            "OPTIONAL MATCH (bb)-[:FLOW_TO]->(succ:BasicBlock) "
            "RETURN bb.address AS block, collect(succ.address) AS successors, "
            "bb.num_instructions AS instructions ORDER BY bb.address"
        ),
        category="cfg",
    ),
]


def get_few_shots(
    category: str | None = None, max_examples: int = 5
) -> list[FewShotExample]:
    """Retrieve few-shot examples, optionally filtered by category."""
    if category:
        filtered = [ex for ex in FEW_SHOT_BANK if ex.category == category]
        return filtered[:max_examples]
    return FEW_SHOT_BANK[:max_examples]


def classify_question(question: str) -> str:
    """Simple keyword-based classification for few-shot selection."""
    q = question.lower()
    if any(w in q for w in ["bbr", "rank", "important", "pagerank"]):
        return "bbr"
    if any(w in q for w in ["import", "malloc", "free", "api", "library"]):
        return "import"
    if any(w in q for w in ["call", "caller", "callee", "call graph"]):
        return "callgraph"
    if any(w in q for w in ["string", "reference", "password", "url"]):
        return "string"
    if any(w in q for w in ["vuln", "dangerous", "unsafe", "strcpy", "overflow"]):
        return "vulnerability"
    if any(w in q for w in ["cfg", "control flow", "flow", "block"]):
        return "cfg"
    if any(w in q for w in ["complex", "large", "big", "count"]):
        return "complexity"
    if any(w in q for w in ["binary", "binaries", "file"]):
        return "binary"
    return "general"
