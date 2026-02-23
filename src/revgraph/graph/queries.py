"""Pre-built Cypher query library for common graph operations."""

from __future__ import annotations

# -- Binary queries --

LIST_BINARIES = """
MATCH (b:BinaryFile)
RETURN b.name AS name, b.sha256 AS sha256, b.architecture AS architecture,
       b.file_type AS file_type, b.word_size AS word_size
ORDER BY b.name
"""

GET_BINARY = """
MATCH (b:BinaryFile {sha256: $sha256})
RETURN b.name AS name, b.sha256 AS sha256, b.architecture AS architecture,
       b.endianness AS endianness, b.file_type AS file_type, b.word_size AS word_size
"""

BINARY_STATS = """
MATCH (b:BinaryFile {sha256: $sha256})
OPTIONAL MATCH (b)-[:DEFINES]->(f:Function)
OPTIONAL MATCH (f)-[:CONTAINS]->(bb:BasicBlock)
RETURN b.name AS name, count(DISTINCT f) AS functions, count(DISTINCT bb) AS basic_blocks
"""

# -- Function queries --

LIST_FUNCTIONS = """
MATCH (b:BinaryFile {sha256: $sha256})-[:DEFINES]->(f:Function)
RETURN f.name AS name, f.address AS address, f.size AS size
ORDER BY f.address
LIMIT $limit
"""

GET_FUNCTION = """
MATCH (f:Function {address: $address, binary_sha256: $sha256})
RETURN f.name AS name, f.address AS address, f.size AS size,
       f.decompiled_code AS decompiled_code, f.summary AS summary, f.label AS label
"""

FUNCTION_CALLERS = """
MATCH (caller:Function)-[:CALLS]->(f:Function {address: $address, binary_sha256: $sha256})
RETURN caller.name AS name, caller.address AS address
ORDER BY caller.address
"""

FUNCTION_CALLEES = """
MATCH (f:Function {address: $address, binary_sha256: $sha256})-[:CALLS]->(callee:Function)
RETURN callee.name AS name, callee.address AS address
ORDER BY callee.address
"""

FUNCTION_STRINGS = """
MATCH (f:Function {address: $address, binary_sha256: $sha256})-[:REFERENCES_STRING]->(s:String)
RETURN s.value AS value, s.address AS address
"""

FUNCTION_IMPORTS = """
MATCH (f:Function {address: $address, binary_sha256: $sha256})-[:REFERENCES_IMPORT]->(i:Import)
RETURN i.name AS name, i.library AS library, i.address AS address
"""

# -- BasicBlock queries --

FUNCTION_CFG = """
MATCH (f:Function {address: $address, binary_sha256: $sha256})-[:CONTAINS]->(bb:BasicBlock)
OPTIONAL MATCH (bb)-[:FLOW_TO]->(succ:BasicBlock)
RETURN bb.address AS block_address, bb.size AS block_size,
       bb.num_instructions AS num_instructions, bb.bbr_score AS bbr_score,
       collect(succ.address) AS successors
ORDER BY bb.address
"""

# -- BBR queries --

TOP_BBR_BLOCKS = """
MATCH (bb:BasicBlock {binary_sha256: $sha256})
WHERE bb.bbr_score IS NOT NULL
RETURN bb.address AS address, bb.bbr_score AS bbr_score
ORDER BY bb.bbr_score DESC
LIMIT $limit
"""

TOP_BBR_FUNCTIONS = """
MATCH (f:Function {binary_sha256: $sha256})-[:CONTAINS]->(bb:BasicBlock)
WHERE bb.bbr_score IS NOT NULL
WITH f, avg(bb.bbr_score) AS avg_bbr, max(bb.bbr_score) AS max_bbr
RETURN f.name AS name, f.address AS address, avg_bbr, max_bbr
ORDER BY max_bbr DESC
LIMIT $limit
"""

# -- String/Import search --

SEARCH_STRINGS = """
CALL db.index.fulltext.queryNodes('string_value_ft', $query) YIELD node, score
RETURN node.value AS value, node.address AS address, node.binary_sha256 AS binary, score
LIMIT $limit
"""

SEARCH_FUNCTIONS_BY_NAME = """
CALL db.index.fulltext.queryNodes('func_name_ft', $query) YIELD node, score
RETURN node.name AS name, node.address AS address, node.binary_sha256 AS binary, score
LIMIT $limit
"""

FUNCTIONS_CALLING_IMPORT = """
MATCH (f:Function)-[:REFERENCES_IMPORT]->(i:Import)
WHERE i.name = $import_name
RETURN DISTINCT f.name AS function_name, f.address AS address,
       f.binary_sha256 AS binary, i.library AS library
"""

# -- Cross-binary --

SHARED_IMPORTS = """
MATCH (f1:Function {binary_sha256: $sha256_a})-[:REFERENCES_IMPORT]->(i:Import)
      <-[:REFERENCES_IMPORT]-(f2:Function {binary_sha256: $sha256_b})
RETURN i.name AS import_name, i.library AS library,
       f1.name AS func_a, f2.name AS func_b
"""
