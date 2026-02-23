"""MCP server for binary extraction via Blackfyre."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

_loaded_artifacts: dict[str, object] = {}


def create_blackfyre_server() -> FastMCP:
    mcp = FastMCP("revgraph-blackfyre")

    @mcp.tool()
    def load_bcc(path: str, lift_vex: bool = False) -> dict:
        """Load a BCC protobuf file and return binary metadata."""
        from pathlib import Path
        from revgraph.extraction.bcc_loader import load_bcc_file

        artifact = load_bcc_file(Path(path), lift_vex=lift_vex)
        if artifact is None:
            return {"error": f"Failed to load {path}"}

        _loaded_artifacts[artifact.sha256] = artifact
        return {
            "name": artifact.name,
            "sha256": artifact.sha256,
            "architecture": artifact.architecture,
            "num_functions": len(artifact.functions),
            "num_strings": len(artifact.strings),
            "num_imports": len(artifact.imports),
        }

    @mcp.tool()
    def list_functions(sha256: str) -> list[dict]:
        """List all functions in a loaded binary."""
        artifact = _loaded_artifacts.get(sha256)
        if artifact is None:
            return [{"error": f"Binary {sha256} not loaded"}]

        return [
            {"name": f.name, "address": hex(f.address), "size": f.size}
            for f in artifact.functions
        ]

    @mcp.tool()
    def get_function(sha256: str, address: str) -> dict:
        """Get detailed info about a specific function."""
        artifact = _loaded_artifacts.get(sha256)
        if artifact is None:
            return {"error": f"Binary {sha256} not loaded"}

        addr = int(address, 16) if address.startswith("0x") else int(address)
        for f in artifact.functions:
            if f.address == addr:
                return {
                    "name": f.name,
                    "address": hex(f.address),
                    "size": f.size,
                    "decompiled_code": f.decompiled_code[:4000],
                    "num_basic_blocks": len(f.basic_blocks),
                    "callees": [hex(c) for c in f.callees],
                    "strings": [s.value for s in f.strings],
                    "imports": [{"name": i.name, "library": i.library} for i in f.imports],
                }
        return {"error": f"Function at {address} not found"}

    @mcp.tool()
    def get_strings(sha256: str) -> list[dict]:
        """Get all strings from a loaded binary."""
        artifact = _loaded_artifacts.get(sha256)
        if artifact is None:
            return [{"error": f"Binary {sha256} not loaded"}]

        return [
            {"value": s.value, "address": hex(s.address)}
            for s in artifact.strings
        ]

    @mcp.tool()
    def get_imports(sha256: str) -> list[dict]:
        """Get all imports from a loaded binary."""
        artifact = _loaded_artifacts.get(sha256)
        if artifact is None:
            return [{"error": f"Binary {sha256} not loaded"}]

        return [
            {"name": i.name, "library": i.library, "address": hex(i.address)}
            for i in artifact.imports
        ]

    @mcp.tool()
    def get_cfg(sha256: str, function_address: str) -> dict:
        """Get the control flow graph of a function."""
        artifact = _loaded_artifacts.get(sha256)
        if artifact is None:
            return {"error": f"Binary {sha256} not loaded"}

        addr = int(function_address, 16) if function_address.startswith("0x") else int(function_address)
        for f in artifact.functions:
            if f.address == addr:
                blocks = []
                for bb in f.basic_blocks:
                    blocks.append(
                        {
                            "address": hex(bb.address),
                            "size": bb.size,
                            "num_instructions": bb.num_instructions,
                            "successors": [hex(s) for s in bb.successors],
                        }
                    )
                return {"function": f.name, "blocks": blocks}
        return {"error": f"Function at {function_address} not found"}

    return mcp
