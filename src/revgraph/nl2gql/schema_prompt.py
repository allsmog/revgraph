"""Build schema-constrained prompts for NL2Cypher translation."""

from __future__ import annotations

from neo4j import Driver

SCHEMA_DESCRIPTION = """
Nodes:
  (:BinaryFile {name, sha256, architecture, endianness, file_type, word_size})
  (:Function {name, address, size, decompiled_code, binary_sha256, summary, label})
  (:BasicBlock {address, size, num_instructions, binary_sha256, bbr_score})
  (:Instruction {address, mnemonic, opcode, category, binary_sha256, vex_ir})
  (:String {value, address, binary_sha256, bbr_score})
  (:Import {name, library, address, binary_sha256, bbr_score})
  (:Embedding {id, vector, model, dimensions, type, source_address, binary_sha256})

Relationships:
  (:BinaryFile)-[:DEFINES]->(:Function)
  (:Function)-[:CALLS]->(:Function)
  (:Function)-[:CONTAINS]->(:BasicBlock)
  (:BasicBlock)-[:FLOW_TO]->(:BasicBlock)
  (:BasicBlock)-[:CONTAINS]->(:Instruction)
  (:Function)-[:REFERENCES_STRING]->(:String)
  (:Function)-[:REFERENCES_IMPORT]->(:Import)
  (:Function)-[:HAS_EMBEDDING]->(:Embedding)

Constraints:
  - (Function.address, Function.binary_sha256) is unique
  - (BasicBlock.address, BasicBlock.binary_sha256) is unique
  - (Instruction.address, Instruction.binary_sha256) is unique
  - BinaryFile.sha256 is unique

Indexes:
  - Full-text on Function.name and String.value
  - Vector index on Embedding.vector (cosine similarity)
"""


def get_schema_prompt(driver: Driver | None = None) -> str:
    """Return the graph schema description for LLM prompts.

    If a driver is provided, augment with live statistics.
    """
    if driver is None:
        return SCHEMA_DESCRIPTION

    stats_lines = [SCHEMA_DESCRIPTION, "\nCurrent graph statistics:"]
    try:
        with driver.session() as session:
            for label in ["BinaryFile", "Function", "BasicBlock", "Instruction", "String", "Import"]:
                result = session.run(f"MATCH (n:{label}) RETURN count(n) AS cnt")
                cnt = result.single()["cnt"]
                stats_lines.append(f"  {label}: {cnt} nodes")
    except Exception:
        pass

    return "\n".join(stats_lines)
