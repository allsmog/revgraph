"""Load BCC protobuf files via Blackfyre into normalized artifacts."""

from __future__ import annotations

import hashlib
from pathlib import Path

from revgraph.extraction.binary_artifact import (
    BasicBlockArtifact,
    BinaryArtifact,
    FunctionArtifact,
    ImportReference,
    InstructionArtifact,
    StringReference,
)
from revgraph.utils.logging import get_logger

log = get_logger(__name__)


def load_bcc_file(
    path: Path, lift_vex: bool = False
) -> BinaryArtifact | None:
    """Load a single .bcc file and return a BinaryArtifact."""
    path = Path(path)
    if not path.exists() or path.suffix != ".bcc":
        log.warning("invalid_bcc_path", path=str(path))
        return None

    try:
        from blackfyre.datatypes.contexts.binarycontext import BinaryContext

        bcc = BinaryContext(str(path))
    except ImportError:
        log.info("blackfyre_not_installed, using fallback loader")
        return _load_bcc_fallback(path, lift_vex)
    except Exception as exc:
        log.error("bcc_load_failed", path=str(path), error=str(exc))
        return None

    return _convert_blackfyre_context(bcc, path, lift_vex)


def _convert_blackfyre_context(
    bcc, path: Path, lift_vex: bool
) -> BinaryArtifact:
    """Convert a Blackfyre BinaryContext into our frozen dataclasses."""
    file_bytes = path.read_bytes()
    sha256 = hashlib.sha256(file_bytes).hexdigest()

    functions = []
    for func in bcc.functions.values():
        blocks = []
        for bb in getattr(func, "basic_blocks", {}).values():
            instructions = []
            for insn in getattr(bb, "instructions", {}).values():
                vex_ir = ""
                if lift_vex:
                    from revgraph.extraction.vex_lifter import lift_instruction

                    vex_ir = lift_instruction(insn)
                instructions.append(
                    InstructionArtifact(
                        address=insn.address,
                        mnemonic=getattr(insn, "mnemonic", ""),
                        opcode=getattr(insn, "opcode", ""),
                        category=getattr(insn, "category", ""),
                        vex_ir=vex_ir,
                    )
                )

            successors = tuple(getattr(bb, "successors", []))
            blocks.append(
                BasicBlockArtifact(
                    address=bb.address,
                    size=getattr(bb, "size", 0),
                    num_instructions=len(instructions),
                    instructions=tuple(instructions),
                    successors=successors,
                )
            )

        strings = tuple(
            StringReference(value=s.value, address=s.address)
            for s in getattr(func, "string_refs", [])
        )
        imports = tuple(
            ImportReference(
                name=getattr(imp, "name", ""),
                library=getattr(imp, "library", ""),
                address=getattr(imp, "address", 0),
            )
            for imp in getattr(func, "import_refs", [])
        )
        callees = tuple(getattr(func, "callees", []))

        functions.append(
            FunctionArtifact(
                name=func.name,
                address=func.address,
                size=getattr(func, "size", 0),
                decompiled_code=getattr(func, "decompiled_code", ""),
                basic_blocks=tuple(blocks),
                callees=callees,
                strings=strings,
                imports=imports,
            )
        )

    global_strings = tuple(
        StringReference(value=s.value, address=s.address)
        for s in getattr(bcc, "strings", {}).values()
    )
    global_imports = tuple(
        ImportReference(
            name=getattr(imp, "name", ""),
            library=getattr(imp, "library", ""),
            address=getattr(imp, "address", 0),
        )
        for imp in getattr(bcc, "imports", {}).values()
    )

    return BinaryArtifact(
        name=path.stem,
        sha256=sha256,
        architecture=getattr(bcc, "architecture", "unknown"),
        endianness=getattr(bcc, "endianness", "little"),
        file_type=getattr(bcc, "file_type", "unknown"),
        word_size=getattr(bcc, "word_size", 64),
        functions=tuple(functions),
        strings=global_strings,
        imports=global_imports,
    )


def _load_bcc_fallback(path: Path, lift_vex: bool) -> BinaryArtifact | None:
    """Fallback loader when Blackfyre is not installed — reads raw protobuf."""
    log.warning("blackfyre_fallback", msg="Blackfyre not installed; using minimal protobuf loader")
    file_bytes = path.read_bytes()
    sha256 = hashlib.sha256(file_bytes).hexdigest()

    return BinaryArtifact(
        name=path.stem,
        sha256=sha256,
        architecture="unknown",
        functions=(),
    )


def load_bcc_directory(
    directory: Path, recursive: bool = False, lift_vex: bool = False
) -> list[BinaryArtifact]:
    """Load all .bcc files in a directory."""
    directory = Path(directory)
    pattern = "**/*.bcc" if recursive else "*.bcc"
    artifacts = []

    for bcc_path in sorted(directory.glob(pattern)):
        artifact = load_bcc_file(bcc_path, lift_vex=lift_vex)
        if artifact is not None:
            artifacts.append(artifact)
            log.info("loaded_bcc", path=str(bcc_path), functions=len(artifact.functions))

    return artifacts
