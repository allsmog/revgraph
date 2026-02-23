"""Default configuration values and paths."""

from __future__ import annotations

from pathlib import Path

CONFIG_FILE_NAMES = [
    "revgraph.yaml",
    "revgraph.yml",
    ".revgraph.yaml",
    ".revgraph.yml",
]

CONFIG_SEARCH_PATHS = [
    Path.cwd(),
    Path.home() / ".config" / "revgraph",
    Path.home(),
]

DEFAULT_BATCH_SIZE = 1000
DEFAULT_LIMIT = 50
DEFAULT_BBR_ITERATIONS = 20
DEFAULT_BBR_DAMPING = 0.85
DEFAULT_EMBEDDING_DIMENSIONS = 3072
DEFAULT_MAX_TURNS = 30
