"""NL2GQL dataset generation for fine-tuning."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from neo4j import Driver

from revgraph.nl2gql.few_shot import FEW_SHOT_BANK
from revgraph.utils.logging import get_logger

log = get_logger(__name__)


def generate_nl2cypher_dataset(
    driver: Driver,
    output_path: str | Path,
    num_augmented: int = 100,
    llm_client=None,
) -> int:
    """Generate a training dataset for NL2Cypher fine-tuning.

    Combines hand-written examples with LLM-augmented examples.
    """
    dataset = []

    # 1. Include all hand-written few-shot examples
    for ex in FEW_SHOT_BANK:
        dataset.append(
            {
                "instruction": "Translate the following natural language question to a Neo4j Cypher query.",
                "input": ex.question,
                "output": ex.cypher,
                "category": ex.category,
                "source": "manual",
            }
        )

    # 2. Generate augmented examples using LLM
    if llm_client and num_augmented > 0:
        augmented = _generate_augmented(llm_client, driver, num_augmented)
        dataset.extend(augmented)

    # 3. Write dataset
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(dataset, indent=2))

    log.info("dataset_generated", total=len(dataset), path=str(output_path))
    return len(dataset)


def _generate_augmented(
    llm_client, driver: Driver, count: int
) -> list[dict[str, Any]]:
    """Use LLM to generate additional NL/Cypher pairs."""
    from revgraph.nl2gql.schema_prompt import get_schema_prompt

    schema = get_schema_prompt(driver)
    examples = []
    batch_size = 10

    for i in range(0, count, batch_size):
        prompt = (
            f"Generate {min(batch_size, count - i)} diverse natural language questions "
            f"about a reverse engineering graph database and their corresponding Cypher queries.\n\n"
            f"Schema:\n{schema}\n\n"
            f"Output as JSON array: [{{\"question\": \"...\", \"cypher\": \"...\", \"category\": \"...\"}}]\n"
            f"Categories: binary, import, callgraph, string, bbr, vulnerability, cfg, complexity"
        )

        raw = llm_client.complete(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
        )

        try:
            # Extract JSON
            raw = raw.strip()
            if "```" in raw:
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            pairs = json.loads(raw)
            for pair in pairs:
                examples.append(
                    {
                        "instruction": "Translate the following natural language question to a Neo4j Cypher query.",
                        "input": pair["question"],
                        "output": pair["cypher"],
                        "category": pair.get("category", "general"),
                        "source": "augmented",
                    }
                )
        except (json.JSONDecodeError, KeyError):
            log.warning("augmentation_parse_error", batch=i)

    return examples


def convert_to_alpaca_format(
    input_path: str | Path, output_path: str | Path
) -> None:
    """Convert dataset to Alpaca format for LLaMAFactory."""
    data = json.loads(Path(input_path).read_text())
    alpaca = [
        {
            "instruction": item["instruction"],
            "input": item["input"],
            "output": item["output"],
        }
        for item in data
    ]
    Path(output_path).write_text(json.dumps(alpaca, indent=2))
