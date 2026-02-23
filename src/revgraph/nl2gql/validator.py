"""Cypher query validation."""

from __future__ import annotations

import re

from revgraph.utils.logging import get_logger

log = get_logger(__name__)

# Valid Cypher clause starters
VALID_STARTERS = {
    "MATCH", "OPTIONAL", "CREATE", "MERGE", "DELETE", "DETACH",
    "SET", "REMOVE", "RETURN", "WITH", "UNWIND", "CALL", "UNION",
    "FOREACH", "LOAD", "USING",
}

# Dangerous write operations we may want to block in read-only contexts
WRITE_CLAUSES = {"CREATE", "MERGE", "DELETE", "DETACH DELETE", "SET", "REMOVE"}

# Known node labels in our schema
KNOWN_LABELS = {
    "BinaryFile", "Function", "BasicBlock", "Instruction",
    "String", "Import", "Embedding",
}

# Known relationship types
KNOWN_RELATIONSHIPS = {
    "DEFINES", "CALLS", "CONTAINS", "FLOW_TO",
    "REFERENCES_STRING", "REFERENCES_IMPORT", "HAS_EMBEDDING",
}


def validate_cypher(
    query: str, allow_writes: bool = False
) -> tuple[bool, str]:
    """Validate a Cypher query. Returns (is_valid, error_message)."""
    query = query.strip()
    if not query:
        return False, "Empty query"

    # Strip markdown code fences if present
    query = _strip_code_fences(query)

    # Check for balanced parentheses and brackets
    if not _check_balanced(query, "(", ")"):
        return False, "Unbalanced parentheses"
    if not _check_balanced(query, "[", "]"):
        return False, "Unbalanced brackets"
    if not _check_balanced(query, "{", "}"):
        return False, "Unbalanced braces"

    # Check starts with valid clause
    first_word = query.split()[0].upper() if query.split() else ""
    if first_word not in VALID_STARTERS:
        return False, f"Query must start with a valid Cypher clause, got: {first_word}"

    # Check for write operations in read-only mode
    if not allow_writes:
        upper_query = query.upper()
        for clause in WRITE_CLAUSES:
            # Only flag standalone write clauses, not those inside strings
            pattern = rf'\b{clause}\b'
            if re.search(pattern, upper_query) and clause != "SET":
                return False, f"Write operation '{clause}' not allowed in read-only mode"

    # Check for RETURN clause (most queries need one)
    if "RETURN" not in query.upper() and "DELETE" not in query.upper():
        return False, "Query should include a RETURN clause"

    return True, ""


def sanitize_cypher(query: str) -> str:
    """Clean and normalize a Cypher query from LLM output."""
    query = _strip_code_fences(query)
    query = query.strip().rstrip(";")
    # Remove any leading explanatory text
    lines = query.split("\n")
    cypher_lines = []
    started = False
    for line in lines:
        stripped = line.strip()
        if not started:
            first_word = stripped.split()[0].upper() if stripped.split() else ""
            if first_word in VALID_STARTERS:
                started = True
        if started:
            cypher_lines.append(line)
    return "\n".join(cypher_lines) if cypher_lines else query


def _strip_code_fences(query: str) -> str:
    """Remove markdown code fences."""
    query = re.sub(r"^```(?:cypher)?\s*\n?", "", query.strip())
    query = re.sub(r"\n?```\s*$", "", query.strip())
    return query


def _check_balanced(text: str, open_char: str, close_char: str) -> bool:
    """Check if characters are balanced, ignoring those inside strings."""
    depth = 0
    in_string = False
    string_char = None
    for ch in text:
        if in_string:
            if ch == string_char:
                in_string = False
        elif ch in ("'", '"'):
            in_string = True
            string_char = ch
        elif ch == open_char:
            depth += 1
        elif ch == close_char:
            depth -= 1
            if depth < 0:
                return False
    return depth == 0
