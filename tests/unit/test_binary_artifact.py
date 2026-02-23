"""Tests for frozen binary artifact dataclasses."""

import pytest
from dataclasses import FrozenInstanceError

from revgraph.extraction.binary_artifact import (
    BasicBlockArtifact,
    BinaryArtifact,
    FunctionArtifact,
    ImportReference,
    InstructionArtifact,
    StringReference,
)


def test_instruction_artifact_frozen():
    insn = InstructionArtifact(address=0x1000, mnemonic="mov", opcode="89")
    with pytest.raises(FrozenInstanceError):
        insn.address = 0x2000


def test_basic_block_artifact():
    bb = BasicBlockArtifact(
        address=0x1000,
        size=20,
        num_instructions=3,
        successors=(0x1020,),
    )
    assert bb.address == 0x1000
    assert bb.size == 20
    assert bb.successors == (0x1020,)


def test_function_artifact():
    func = FunctionArtifact(
        name="main",
        address=0x401000,
        size=100,
        callees=(0x402000,),
    )
    assert func.name == "main"
    assert func.callees == (0x402000,)
    assert func.basic_blocks == ()


def test_binary_artifact(sample_artifact):
    assert sample_artifact.name == "test_binary"
    assert sample_artifact.sha256 == "a" * 64
    assert len(sample_artifact.functions) == 2
    assert sample_artifact.architecture == "x86_64"


def test_binary_artifact_frozen(sample_artifact):
    with pytest.raises(FrozenInstanceError):
        sample_artifact.name = "modified"


def test_string_reference():
    s = StringReference(value="hello world", address=0x5000)
    assert s.value == "hello world"
    assert s.address == 0x5000


def test_import_reference():
    imp = ImportReference(name="malloc", library="libc.so.6", address=0x6000)
    assert imp.name == "malloc"
    assert imp.library == "libc.so.6"
