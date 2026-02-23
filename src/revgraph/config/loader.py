"""YAML configuration loader with env var interpolation."""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

from revgraph.config.defaults import CONFIG_FILE_NAMES, CONFIG_SEARCH_PATHS
from revgraph.config.models import RevGraphConfig

_ENV_VAR_PATTERN = re.compile(r"\$\{(\w+)(?::([^}]*))?\}")


def _interpolate_env(value: str) -> str:
    """Replace ${VAR} or ${VAR:default} with environment variable values."""

    def _replace(match: re.Match[str]) -> str:
        var_name = match.group(1)
        default = match.group(2)
        return os.environ.get(var_name, default if default is not None else "")

    return _ENV_VAR_PATTERN.sub(_replace, value)


def _walk_and_interpolate(obj: object) -> object:
    if isinstance(obj, str):
        return _interpolate_env(obj)
    if isinstance(obj, dict):
        return {k: _walk_and_interpolate(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk_and_interpolate(item) for item in obj]
    return obj


def find_config_file(explicit_path: str | Path | None = None) -> Path | None:
    """Locate a revgraph config file, returning the first found or None."""
    if explicit_path is not None:
        p = Path(explicit_path)
        return p if p.is_file() else None

    for search_dir in CONFIG_SEARCH_PATHS:
        for name in CONFIG_FILE_NAMES:
            candidate = search_dir / name
            if candidate.is_file():
                return candidate
    return None


def load_config(path: str | Path | None = None) -> RevGraphConfig:
    """Load and validate configuration, falling back to defaults."""
    config_path = find_config_file(path)
    if config_path is None:
        return RevGraphConfig()

    raw = yaml.safe_load(config_path.read_text()) or {}
    interpolated = _walk_and_interpolate(raw)
    return RevGraphConfig.model_validate(interpolated)
