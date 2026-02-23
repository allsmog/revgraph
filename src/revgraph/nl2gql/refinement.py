"""Error-feedback refinement loop for NL2Cypher."""

from __future__ import annotations

from revgraph.llm.client import LLMClient
from revgraph.utils.logging import get_logger

log = get_logger(__name__)

REFINEMENT_PROMPT = """The following Cypher query produced an error when executed against Neo4j.

Original question: {question}
Generated Cypher: {cypher}
Error: {error}

Please fix the Cypher query. Output ONLY the corrected Cypher, no explanations.
Remember the graph schema:
{schema}
"""

MAX_REFINEMENT_ATTEMPTS = 3


def refine_query(
    llm: LLMClient,
    question: str,
    cypher: str,
    error: str,
    schema: str,
    attempt: int = 0,
) -> str | None:
    """Attempt to fix a failed Cypher query using LLM feedback."""
    if attempt >= MAX_REFINEMENT_ATTEMPTS:
        log.warning("refinement_exhausted", question=question, attempts=attempt)
        return None

    prompt = REFINEMENT_PROMPT.format(
        question=question,
        cypher=cypher,
        error=error,
        schema=schema,
    )

    refined = llm.complete(
        messages=[{"role": "user", "content": prompt}],
        temperature=0.0,
    )

    from revgraph.nl2gql.validator import sanitize_cypher

    return sanitize_cypher(refined)
