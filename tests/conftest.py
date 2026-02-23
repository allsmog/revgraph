"""Shared test fixtures."""

from __future__ import annotations

import pytest

from revgraph.config.models import (
    LLMConfig,
    Neo4jConfig,
    RevGraphConfig,
)
from revgraph.extraction.binary_artifact import (
    BasicBlockArtifact,
    BinaryArtifact,
    FunctionArtifact,
    ImportReference,
    InstructionArtifact,
    StringReference,
)


@pytest.fixture
def sample_config() -> RevGraphConfig:
    return RevGraphConfig(
        neo4j=Neo4jConfig(
            uri="bolt://localhost:7687",
            username="neo4j",
            password="testpassword",
        ),
        llm=LLMConfig(
            default_model="gpt-3.5-turbo",
            temperature=0.0,
        ),
    )


@pytest.fixture
def sample_artifact() -> BinaryArtifact:
    """Create a sample BinaryArtifact for testing."""
    instructions = (
        InstructionArtifact(address=0x401000, mnemonic="push", opcode="55", category="stack"),
        InstructionArtifact(address=0x401001, mnemonic="mov", opcode="89e5", category="data"),
        InstructionArtifact(address=0x401003, mnemonic="call", opcode="e8", category="control"),
    )

    bb1 = BasicBlockArtifact(
        address=0x401000,
        size=20,
        num_instructions=3,
        instructions=instructions,
        successors=(0x401020,),
    )
    bb2 = BasicBlockArtifact(
        address=0x401020,
        size=15,
        num_instructions=2,
        instructions=(
            InstructionArtifact(address=0x401020, mnemonic="ret", opcode="c3", category="control"),
            InstructionArtifact(address=0x401021, mnemonic="nop", opcode="90", category="other"),
        ),
        successors=(),
    )

    func_main = FunctionArtifact(
        name="main",
        address=0x401000,
        size=50,
        decompiled_code="int main() { printf(\"hello\"); return 0; }",
        basic_blocks=(bb1, bb2),
        callees=(0x402000,),
        strings=(StringReference(value="hello", address=0x500000),),
        imports=(ImportReference(name="printf", library="libc.so.6", address=0x600000),),
    )

    func_helper = FunctionArtifact(
        name="helper",
        address=0x402000,
        size=30,
        decompiled_code="void helper() { strcpy(buf, input); }",
        basic_blocks=(),
        callees=(),
        strings=(),
        imports=(
            ImportReference(name="strcpy", library="libc.so.6", address=0x600010),
        ),
    )

    return BinaryArtifact(
        name="test_binary",
        sha256="a" * 64,
        architecture="x86_64",
        endianness="little",
        file_type="ELF",
        word_size=64,
        functions=(func_main, func_helper),
        strings=(
            StringReference(value="hello", address=0x500000),
            StringReference(value="/bin/sh", address=0x500010),
        ),
        imports=(
            ImportReference(name="printf", library="libc.so.6", address=0x600000),
            ImportReference(name="strcpy", library="libc.so.6", address=0x600010),
        ),
    )


@pytest.fixture
def neo4j_driver(sample_config):
    """Create a Neo4j driver for integration tests.

    Uses testcontainers when available, otherwise connects to localhost.
    """
    try:
        from testcontainers.neo4j import Neo4jContainer

        container = Neo4jContainer("neo4j:5-community")
        container.start()
        uri = container.get_connection_url()

        from neo4j import GraphDatabase

        driver = GraphDatabase.driver(uri, auth=("neo4j", "test"))
        yield driver
        driver.close()
        container.stop()
    except ImportError:
        pytest.skip("testcontainers not installed")


# Markers
def pytest_configure(config):
    config.addinivalue_line("markers", "integration: requires running Neo4j")
