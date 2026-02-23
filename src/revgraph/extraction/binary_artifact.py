"""Frozen dataclasses representing extracted binary artifacts."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class InstructionArtifact:
    address: int
    mnemonic: str
    opcode: str
    category: str = ""
    vex_ir: str = ""


@dataclass(frozen=True)
class BasicBlockArtifact:
    address: int
    size: int
    num_instructions: int
    instructions: tuple[InstructionArtifact, ...] = ()
    successors: tuple[int, ...] = ()  # addresses of successor blocks


@dataclass(frozen=True)
class StringReference:
    value: str
    address: int


@dataclass(frozen=True)
class ImportReference:
    name: str
    library: str
    address: int


@dataclass(frozen=True)
class FunctionArtifact:
    name: str
    address: int
    size: int
    decompiled_code: str = ""
    basic_blocks: tuple[BasicBlockArtifact, ...] = ()
    callees: tuple[int, ...] = ()  # addresses of called functions
    strings: tuple[StringReference, ...] = ()
    imports: tuple[ImportReference, ...] = ()


@dataclass(frozen=True)
class BinaryArtifact:
    name: str
    sha256: str
    architecture: str
    endianness: str = "little"
    file_type: str = "ELF"
    word_size: int = 64
    functions: tuple[FunctionArtifact, ...] = ()
    strings: tuple[StringReference, ...] = ()
    imports: tuple[ImportReference, ...] = ()
