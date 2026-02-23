"""vLLM serving configuration for fine-tuned models."""

from __future__ import annotations

from typing import Any

from revgraph.utils.logging import get_logger

log = get_logger(__name__)


def generate_vllm_config(
    model_path: str,
    port: int = 8000,
    gpu_memory_utilization: float = 0.9,
    max_model_len: int = 4096,
) -> dict[str, Any]:
    """Generate a vLLM serving configuration."""
    return {
        "model": model_path,
        "host": "0.0.0.0",
        "port": port,
        "gpu_memory_utilization": gpu_memory_utilization,
        "max_model_len": max_model_len,
        "dtype": "auto",
        "trust_remote_code": True,
    }


def generate_litellm_proxy_config(
    model_path: str,
    model_name: str = "revgraph-nl2cypher",
    vllm_base_url: str = "http://localhost:8000/v1",
) -> dict[str, Any]:
    """Generate a LiteLLM config snippet for the fine-tuned model."""
    return {
        "model_list": [
            {
                "model_name": model_name,
                "litellm_params": {
                    "model": f"openai/{model_path}",
                    "api_base": vllm_base_url,
                    "api_key": "not-needed",
                },
            }
        ]
    }


def start_vllm_server(
    model_path: str, port: int = 8000, background: bool = True
) -> None:
    """Start a vLLM server for the fine-tuned model."""
    import subprocess

    cmd = [
        "python", "-m", "vllm.entrypoints.openai.api_server",
        "--model", model_path,
        "--host", "0.0.0.0",
        "--port", str(port),
    ]

    log.info("starting_vllm", cmd=" ".join(cmd))

    if background:
        subprocess.Popen(cmd)
        log.info("vllm_started_background", port=port)
    else:
        subprocess.run(cmd)
