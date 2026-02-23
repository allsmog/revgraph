"""Direct ELF loader using pyelftools + capstone — no Ghidra required."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

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


def load_elf(path: Path) -> BinaryArtifact | None:
    """Load a raw ELF binary into a BinaryArtifact."""
    path = Path(path)
    if not path.exists():
        log.warning("elf_not_found", path=str(path))
        return None

    file_bytes = path.read_bytes()
    sha256 = hashlib.sha256(file_bytes).hexdigest()

    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            arch = _get_arch(elf)
            endianness = "little" if elf.little_endian else "big"
            word_size = elf.elfclass
            file_type = _get_file_type(elf)

            # Extract components
            symbols = _get_symbols(elf)
            plt_entries = _get_plt_imports(elf, symbols)
            strings = _get_strings(elf)
            functions = _get_functions(elf, symbols, plt_entries)

    except Exception as exc:
        log.error("elf_load_failed", path=str(path), error=str(exc))
        return None

    global_imports = tuple(
        ImportReference(name=name, library="", address=addr)
        for name, addr in plt_entries.items()
    )

    log.info(
        "elf_loaded",
        path=str(path),
        functions=len(functions),
        strings=len(strings),
        imports=len(global_imports),
    )

    return BinaryArtifact(
        name=path.stem,
        sha256=sha256,
        architecture=arch,
        endianness=endianness,
        file_type=file_type,
        word_size=word_size,
        functions=tuple(functions),
        strings=tuple(strings),
        imports=global_imports,
    )


def _get_arch(elf: ELFFile) -> str:
    machine = elf.header.e_machine
    mapping = {
        "EM_X86_64": "x86_64",
        "EM_386": "x86",
        "EM_ARM": "ARM",
        "EM_AARCH64": "AArch64",
        "EM_MIPS": "MIPS",
        "EM_PPC": "PPC",
        "EM_PPC64": "PPC64",
    }
    return mapping.get(machine, str(machine))


def _get_file_type(elf: ELFFile) -> str:
    et = elf.header.e_type
    mapping = {
        "ET_EXEC": "executable",
        "ET_DYN": "shared_object",
        "ET_REL": "relocatable",
    }
    return mapping.get(et, str(et))


def _get_symbols(elf: ELFFile) -> dict[str, dict[str, Any]]:
    """Extract all symbols from .symtab and .dynsym."""
    symbols: dict[str, dict[str, Any]] = {}
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for sym in section.iter_symbols():
            if sym.name and sym.entry.st_value:
                symbols[sym.name] = {
                    "address": sym.entry.st_value,
                    "size": sym.entry.st_size,
                    "type": sym.entry.st_info.type,
                    "bind": sym.entry.st_info.bind,
                    "section_index": sym.entry.st_shndx,
                }
    return symbols


def _get_plt_imports(elf: ELFFile, symbols: dict) -> dict[str, int]:
    """Identify PLT import stubs by parsing .rela.plt relocations."""
    imports: dict[str, int] = {}

    # Get PLT section layout
    plt_section = elf.get_section_by_name(".plt")
    if not plt_section:
        return imports
    plt_base = plt_section["sh_addr"]
    plt_entry_size = 16  # Standard x86_64 PLT entry size

    # Get .dynsym for symbol name resolution
    dynsym = elf.get_section_by_name(".dynsym")
    if not dynsym:
        return imports

    # Parse .rela.plt — entries are in PLT stub order
    rela_plt = elf.get_section_by_name(".rela.plt")
    if rela_plt:
        from elftools.elf.relocation import RelocationSection

        if isinstance(rela_plt, RelocationSection):
            for i, rel in enumerate(rela_plt.iter_relocations()):
                sym_idx = rel.entry.r_info_sym
                sym = dynsym.get_symbol(sym_idx)
                if sym and sym.name:
                    # PLT[0] is the resolver, actual entries start at PLT[1]
                    stub_addr = plt_base + (i + 1) * plt_entry_size
                    imports[sym.name] = stub_addr

    # Also collect undefined dynamic symbols without PLT addresses
    for sym in dynsym.iter_symbols():
        if (
            sym.name
            and sym.entry.st_info.type == "STT_FUNC"
            and sym.entry.st_shndx == "SHN_UNDEF"
            and sym.name not in imports
        ):
            imports[sym.name] = 0

    return imports


def _get_strings(elf: ELFFile) -> list[StringReference]:
    """Extract printable strings from .rodata and .data sections."""
    string_refs: list[StringReference] = []
    for section_name in (".rodata", ".data"):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        data = section.data()
        base_addr = section["sh_addr"]
        current: list[int] = []
        start = 0
        for i, byte in enumerate(data):
            if 0x20 <= byte <= 0x7E:
                if not current:
                    start = i
                current.append(byte)
            else:
                if len(current) >= 4:
                    value = bytes(current).decode("ascii", errors="replace")
                    string_refs.append(StringReference(value=value, address=base_addr + start))
                current = []
        if len(current) >= 4:
            value = bytes(current).decode("ascii", errors="replace")
            string_refs.append(StringReference(value=value, address=base_addr + start))
    return string_refs


def _get_functions(
    elf: ELFFile,
    symbols: dict[str, dict[str, Any]],
    plt_entries: dict[str, int],
) -> list[FunctionArtifact]:
    """Extract user-defined functions with disassembled basic blocks."""
    text_section = elf.get_section_by_name(".text")
    if text_section is None:
        return []

    text_data = text_section.data()
    text_base = text_section["sh_addr"]

    # Set up capstone
    if elf.elfclass == 64:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    # Filter to FUNC symbols in .text
    func_syms = []
    for name, info in symbols.items():
        if info["type"] == "STT_FUNC" and info["size"] > 0:
            addr = info["address"]
            if text_base <= addr < text_base + len(text_data):
                func_syms.append((name, addr, info["size"]))
    func_syms.sort(key=lambda x: x[1])

    # Map all known addresses for call resolution
    addr_to_name: dict[int, str] = {}
    for name, info in symbols.items():
        addr_to_name[info["address"]] = name
    for name, addr in plt_entries.items():
        if addr:
            addr_to_name[addr] = name

    # Also map PLT stub addresses by scanning .plt section entries
    plt_section = elf.get_section_by_name(".plt")
    plt_base = plt_section["sh_addr"] if plt_section else 0
    plt_end = plt_base + plt_section["sh_size"] if plt_section else 0

    plt_got_section = elf.get_section_by_name(".plt.got")
    plt_got_base = plt_got_section["sh_addr"] if plt_got_section else 0
    plt_got_end = plt_got_base + plt_got_section["sh_size"] if plt_got_section else 0

    # Build a set of PLT import names for quick lookup
    plt_import_names: set[str] = set(plt_entries.keys())

    # Map PLT stub addresses: symbols like "fopen@plt" have addresses in .plt
    for name, info in symbols.items():
        addr = info["address"]
        if plt_base <= addr < plt_end or plt_got_base <= addr < plt_got_end:
            clean_name = name.split("@")[0]
            addr_to_name[addr] = clean_name

    functions: list[FunctionArtifact] = []
    for name, addr, size in func_syms:
        # Skip CRT/compiler-generated functions
        if name.startswith(("_", "deregister_", "register_", "frame_", "__")):
            continue

        offset = addr - text_base
        func_bytes = text_data[offset : offset + size]

        instructions: list[InstructionArtifact] = []
        callees: list[int] = []
        func_strings: list[StringReference] = []
        func_imports: list[ImportReference] = []

        for insn in md.disasm(func_bytes, addr):
            instructions.append(
                InstructionArtifact(
                    address=insn.address,
                    mnemonic=insn.mnemonic,
                    opcode=insn.bytes.hex(),
                )
            )

            # Detect call targets
            if insn.mnemonic == "call" and insn.operands:
                op = insn.operands[0]
                if op.type == 2:  # X86_OP_IMM
                    target = op.imm
                    callees.append(target)
                    target_name = addr_to_name.get(target, "")
                    if not target_name:
                        # Try clean name lookup
                        for sname, sinfo in symbols.items():
                            if sinfo["address"] == target:
                                target_name = sname.split("@")[0]
                                break
                    if target_name:
                        clean = target_name.split("@")[0]
                        if clean in plt_import_names or plt_base <= target < plt_end:
                            func_imports.append(
                                ImportReference(name=clean, library="", address=target)
                            )

            # Detect string references (lea with rip-relative)
            if insn.mnemonic == "lea" and len(insn.operands) >= 2:
                op = insn.operands[1]
                if op.type == 3:  # X86_OP_MEM
                    # RIP-relative: target = next_insn_addr + displacement
                    if op.mem.base == 41:  # X86_REG_RIP
                        target_addr = insn.address + insn.size + op.mem.disp
                        # Check if it points to .rodata
                        rodata = elf.get_section_by_name(".rodata")
                        if rodata:
                            ro_base = rodata["sh_addr"]
                            ro_end = ro_base + rodata["sh_size"]
                            if ro_base <= target_addr < ro_end:
                                ro_data = rodata.data()
                                ro_offset = target_addr - ro_base
                                # Read null-terminated string
                                end = ro_data.find(b"\x00", ro_offset)
                                if end == -1:
                                    end = min(ro_offset + 256, len(ro_data))
                                raw = ro_data[ro_offset:end]
                                try:
                                    s = raw.decode("ascii")
                                    if len(s) >= 2:
                                        func_strings.append(
                                            StringReference(value=s, address=target_addr)
                                        )
                                except UnicodeDecodeError:
                                    pass

        # Build a single basic block per function (simplified)
        block = BasicBlockArtifact(
            address=addr,
            size=size,
            num_instructions=len(instructions),
            instructions=tuple(instructions),
            successors=(),
        )

        functions.append(
            FunctionArtifact(
                name=name,
                address=addr,
                size=size,
                basic_blocks=(block,),
                callees=tuple(callees),
                strings=tuple(func_strings),
                imports=tuple(func_imports),
            )
        )

    return functions
