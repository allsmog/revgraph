"""Tests for BCC extraction / loader."""

from pathlib import Path
from unittest.mock import patch

from revgraph.extraction.bcc_loader import load_bcc_file


def test_fallback_loader_no_blackfyre(tmp_path):
    """When Blackfyre is not installed, the fallback loader returns a minimal artifact."""
    bcc_file = tmp_path / "test.bcc"
    bcc_file.write_bytes(b"\x00" * 64)

    with patch.dict("sys.modules", {"blackfyre": None, "blackfyre.datatypes.contexts.binarycontext": None}):
        artifact = load_bcc_file(bcc_file)

    assert artifact is not None
    assert artifact.name == "test"
    assert artifact.architecture == "unknown"
    assert len(artifact.functions) == 0
    assert len(artifact.sha256) == 64


def test_load_nonexistent_file():
    """Loading a non-existent file returns None."""
    result = load_bcc_file(Path("/nonexistent/path/fake.bcc"))
    assert result is None
