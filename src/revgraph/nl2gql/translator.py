"""NL -> Cypher translation pipeline."""

from __future__ import annotations

from neo4j import Driver

from revgraph.llm.client import LLMClient
from revgraph.llm.prompts import NL2CYPHER_SYSTEM, NL2CYPHER_USER
from revgraph.nl2gql.few_shot import classify_question, get_few_shots
from revgraph.nl2gql.refinement import refine_query
from revgraph.nl2gql.schema_prompt import get_schema_prompt
from revgraph.nl2gql.validator import sanitize_cypher, validate_cypher
from revgraph.utils.logging import get_logger

log = get_logger(__name__)


class NL2CypherTranslator:
    """Translate natural language questions to Cypher queries using LLM."""

    def __init__(
        self,
        llm: LLMClient,
        driver: Driver,
        max_refinements: int = 3,
    ) -> None:
        self._llm = llm
        self._driver = driver
        self._max_refinements = max_refinements
        self._schema = get_schema_prompt(driver)

    def translate(self, question: str) -> str:
        """Translate a natural language question to a Cypher query."""
        category = classify_question(question)
        few_shots = get_few_shots(category, max_examples=3)

        system_msg = NL2CYPHER_SYSTEM.render(schema=self._schema)
        user_msg = NL2CYPHER_USER.render(
            question=question,
            few_shots=[{"question": ex.question, "cypher": ex.cypher} for ex in few_shots],
        )

        raw = self._llm.complete(
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.0,
        )

        cypher = sanitize_cypher(raw)
        log.info("nl2cypher_translated", question=question[:80], cypher=cypher[:120])

        # Validate
        is_valid, error = validate_cypher(cypher)
        if not is_valid:
            log.warning("cypher_validation_failed", error=error)
            refined = refine_query(
                self._llm, question, cypher, error, self._schema
            )
            if refined:
                cypher = refined

        return cypher

    def translate_and_execute(
        self, question: str, limit: int = 50
    ) -> tuple[str, list[dict]]:
        """Translate and execute, with error-feedback refinement."""
        cypher = self.translate(question)

        for attempt in range(self._max_refinements + 1):
            try:
                from revgraph.graph.query_engine import QueryEngine

                engine = QueryEngine(self._driver)
                results = engine.execute(cypher, limit=limit)
                return cypher, results
            except Exception as exc:
                log.warning(
                    "cypher_execution_failed",
                    attempt=attempt,
                    error=str(exc),
                )
                if attempt < self._max_refinements:
                    refined = refine_query(
                        self._llm, question, cypher, str(exc), self._schema
                    )
                    if refined:
                        cypher = refined
                    else:
                        raise
                else:
                    raise

        return cypher, []
