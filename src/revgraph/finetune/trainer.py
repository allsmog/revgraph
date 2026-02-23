"""LLaMAFactory integration for fine-tuning NL2Cypher models."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from revgraph.utils.logging import get_logger

log = get_logger(__name__)


def create_training_config(
    dataset_path: str | Path,
    output_dir: str | Path,
    model_name: str = "meta-llama/Llama-3.1-8B-Instruct",
    num_epochs: int = 3,
    learning_rate: float = 2e-4,
    batch_size: int = 4,
    lora_rank: int = 16,
    lora_alpha: int = 32,
) -> dict[str, Any]:
    """Create a LLaMAFactory-compatible training configuration."""
    config = {
        "model_name_or_path": model_name,
        "stage": "sft",
        "do_train": True,
        "finetuning_type": "lora",
        "lora_rank": lora_rank,
        "lora_alpha": lora_alpha,
        "lora_target": "all",
        "dataset": str(dataset_path),
        "template": "llama3",
        "cutoff_len": 2048,
        "output_dir": str(output_dir),
        "per_device_train_batch_size": batch_size,
        "gradient_accumulation_steps": 4,
        "learning_rate": learning_rate,
        "num_train_epochs": num_epochs,
        "lr_scheduler_type": "cosine",
        "warmup_ratio": 0.1,
        "logging_steps": 10,
        "save_steps": 100,
        "fp16": True,
        "report_to": "none",
    }

    config_path = Path(output_dir) / "training_config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, indent=2))

    log.info("training_config_created", path=str(config_path))
    return config


def run_training(config_path: str | Path) -> None:
    """Run fine-tuning using LLaMAFactory CLI."""
    import subprocess

    config_path = Path(config_path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")

    cmd = ["llamafactory-cli", "train", str(config_path)]
    log.info("starting_training", cmd=" ".join(cmd))

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        log.error("training_failed", stderr=result.stderr[:500])
        raise RuntimeError(f"Training failed: {result.stderr[:500]}")

    log.info("training_complete")


def merge_lora(
    base_model: str,
    lora_path: str | Path,
    output_path: str | Path,
) -> None:
    """Merge LoRA adapter with base model."""
    try:
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer

        tokenizer = AutoTokenizer.from_pretrained(base_model)
        model = AutoModelForCausalLM.from_pretrained(base_model)
        model = PeftModel.from_pretrained(model, str(lora_path))
        model = model.merge_and_unload()

        model.save_pretrained(str(output_path))
        tokenizer.save_pretrained(str(output_path))
        log.info("lora_merged", output=str(output_path))
    except ImportError:
        log.error("peft/transformers not installed. pip install revgraph[finetune]")
        raise
