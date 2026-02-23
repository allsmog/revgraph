"""Embedding generation via LiteLLM."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from neo4j import Driver

from revgraph.llm.client import LLMClient
from revgraph.utils.logging import get_logger
from revgraph.utils.progress import progress_context

log = get_logger(__name__)


@dataclass
class EmbeddingResult:
    source_address: int
    source_type: str  # "function" or "block"
    binary_sha256: str
    vector: list[float]
    model: str
    text_used: str = ""


class EmbeddingGenerator:
    """Generate embeddings for binary artifacts using LiteLLM."""

    def __init__(
        self,
        llm: LLMClient,
        model: str = "text-embedding-3-large",
        dimensions: int | None = None,
        batch_size: int = 20,
    ) -> None:
        self._llm = llm
        self._model = model
        self._dimensions = dimensions
        self._batch_size = batch_size

    def generate_for_binary(
        self,
        driver: Driver,
        sha256: str,
        scope: str = "functions",
        bbr_weighted: bool = False,
    ) -> list[EmbeddingResult]:
        """Generate embeddings for all functions/blocks in a binary."""
        texts_and_meta = self._collect_texts(driver, sha256, scope, bbr_weighted)
        if not texts_and_meta:
            return []

        results = []
        texts = [t["text"] for t in texts_and_meta]

        with progress_context("Generating embeddings", len(texts)) as (progress, task_id):
            for i in range(0, len(texts), self._batch_size):
                batch_texts = texts[i : i + self._batch_size]
                batch_meta = texts_and_meta[i : i + self._batch_size]

                vectors = self._llm.embed(
                    batch_texts,
                    model=self._model,
                    dimensions=self._dimensions,
                )

                for vec, meta in zip(vectors, batch_meta):
                    results.append(
                        EmbeddingResult(
                            source_address=meta["address"],
                            source_type=meta["type"],
                            binary_sha256=sha256,
                            vector=vec,
                            model=self._model,
                            text_used=meta["text"][:200],
                        )
                    )
                progress.advance(task_id, len(batch_texts))

        log.info("embeddings_generated", sha256=sha256[:12], count=len(results))
        return results

    def _collect_texts(
        self,
        driver: Driver,
        sha256: str,
        scope: str,
        bbr_weighted: bool,
    ) -> list[dict[str, Any]]:
        """Collect text representations for embedding."""
        texts = []

        with driver.session() as session:
            if scope == "functions":
                result = session.run(
                    "MATCH (f:Function {binary_sha256: $sha256}) "
                    "OPTIONAL MATCH (f)-[:REFERENCES_STRING]->(s:String) "
                    "OPTIONAL MATCH (f)-[:REFERENCES_IMPORT]->(i:Import) "
                    "RETURN f.name AS name, f.address AS address, "
                    "f.decompiled_code AS code, "
                    "collect(DISTINCT s.value) AS strings, "
                    "collect(DISTINCT i.name) AS imports",
                    sha256=sha256,
                )
                for record in result:
                    text = self._build_function_text(
                        record["name"],
                        record["code"] or "",
                        record["strings"],
                        record["imports"],
                    )
                    texts.append(
                        {
                            "text": text,
                            "address": record["address"],
                            "type": "function",
                        }
                    )
            elif scope == "blocks":
                result = session.run(
                    "MATCH (f:Function {binary_sha256: $sha256})"
                    "-[:CONTAINS]->(bb:BasicBlock)"
                    "-[:CONTAINS]->(i:Instruction) "
                    "WITH bb, f, collect(i.mnemonic) AS mnemonics "
                    "RETURN bb.address AS address, f.name AS func_name, "
                    "mnemonics, bb.bbr_score AS bbr_score",
                    sha256=sha256,
                )
                for record in result:
                    text = f"Function: {record['func_name']}\n"
                    text += f"Block at {hex(record['address'])}:\n"
                    text += " ".join(record["mnemonics"])
                    texts.append(
                        {
                            "text": text,
                            "address": record["address"],
                            "type": "block",
                        }
                    )

        return texts

    @staticmethod
    def _build_function_text(
        name: str, code: str, strings: list[str], imports: list[str]
    ) -> str:
        """Build a text representation of a function for embedding."""
        parts = [f"Function: {name}"]
        if code:
            parts.append(f"Code:\n{code[:2000]}")
        if strings:
            parts.append(f"Strings: {', '.join(strings[:20])}")
        if imports:
            parts.append(f"Imports: {', '.join(imports[:20])}")
        return "\n".join(parts)
