"""Tests for configuration loading."""

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from revgraph.config.loader import _interpolate_env, load_config
from revgraph.config.models import RevGraphConfig


def test_default_config():
    config = RevGraphConfig()
    assert config.neo4j.uri == "bolt://localhost:7687"
    assert config.llm.default_model == "sonnet"
    assert config.analysis.bbr.iterations == 20


def test_env_interpolation():
    os.environ["TEST_VAR_RG"] = "hello"
    assert _interpolate_env("${TEST_VAR_RG}") == "hello"
    del os.environ["TEST_VAR_RG"]


def test_env_interpolation_default():
    result = _interpolate_env("${NONEXISTENT_VAR_RG:fallback}")
    assert result == "fallback"


def test_env_interpolation_missing():
    result = _interpolate_env("${NONEXISTENT_VAR_RG}")
    assert result == ""


def test_load_config_from_file():
    config_data = {
        "neo4j": {"uri": "bolt://custom:7687", "password": "secret"},
        "llm": {"default_model": "gpt-4o", "temperature": 0.5},
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(config_data, f)
        f.flush()

        config = load_config(f.name)
        assert config.neo4j.uri == "bolt://custom:7687"
        assert config.neo4j.password == "secret"
        assert config.llm.default_model == "gpt-4o"
        assert config.llm.temperature == 0.5
        # Defaults preserved
        assert config.neo4j.username == "neo4j"

    os.unlink(f.name)


def test_load_config_missing_file():
    config = load_config("/nonexistent/path.yaml")
    assert config == RevGraphConfig()


def test_config_validation():
    config = RevGraphConfig(
        neo4j={"uri": "bolt://localhost:7687"},
        llm={"temperature": 0.5},
    )
    assert config.neo4j.uri == "bolt://localhost:7687"
    assert config.llm.temperature == 0.5
