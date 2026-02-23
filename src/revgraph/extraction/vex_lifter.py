"""VEX IR lifting for instructions (optional, requires pyvex/archinfo)."""

from __future__ import annotations

from revgraph.utils.logging import get_logger

log = get_logger(__name__)


def lift_instruction(insn) -> str:
    """Lift a single instruction to VEX IR representation.

    Requires pyvex and archinfo to be installed.
    Returns empty string if lifting is unavailable.
    """
    try:
        import archinfo
        import pyvex

        arch = archinfo.ArchAMD64()  # Default; can be made configurable
        opcode_bytes = getattr(insn, "opcode_bytes", None)
        if opcode_bytes is None:
            return ""

        irsb = pyvex.lift(opcode_bytes, insn.address, arch, max_inst=1)
        statements = []
        for stmt in irsb.statements:
            statements.append(str(stmt))
        return "\n".join(statements)
    except ImportError:
        log.debug("pyvex_not_available")
        return ""
    except Exception as exc:
        log.debug("vex_lift_failed", address=hex(getattr(insn, "address", 0)), error=str(exc))
        return ""


def lift_block(block_bytes: bytes, address: int, arch_name: str = "AMD64") -> str:
    """Lift a full basic block to VEX IR."""
    try:
        import archinfo
        import pyvex

        arch_cls = getattr(archinfo, f"Arch{arch_name}", archinfo.ArchAMD64)
        arch = arch_cls()
        irsb = pyvex.lift(block_bytes, address, arch)
        return str(irsb)
    except ImportError:
        return ""
    except Exception:
        return ""
