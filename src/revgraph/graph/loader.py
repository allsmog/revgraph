"""Batch UNWIND loading of binary artifacts into Neo4j."""

from __future__ import annotations

from typing import Any

from neo4j import Driver

from revgraph.extraction.binary_artifact import BinaryArtifact
from revgraph.utils.logging import get_logger
from revgraph.utils.progress import progress_context

log = get_logger(__name__)


class GraphLoader:
    """Loads BinaryArtifact data into Neo4j using batched UNWIND transactions."""

    def __init__(self, driver: Driver) -> None:
        self._driver = driver

    def load_binary(
        self, artifact: BinaryArtifact, batch_size: int = 1000, merge: bool = True
    ) -> dict[str, int]:
        """Load a complete binary artifact into the graph. Returns load stats."""
        op = "MERGE" if merge else "CREATE"
        stats: dict[str, int] = {}

        with self._driver.session() as session:
            # 1. BinaryFile node
            session.run(
                f"{op} (b:BinaryFile {{sha256: $sha256}}) "
                "SET b.name = $name, b.architecture = $arch, "
                "b.endianness = $endian, b.file_type = $ftype, b.word_size = $ws",
                sha256=artifact.sha256,
                name=artifact.name,
                arch=artifact.architecture,
                endian=artifact.endianness,
                ftype=artifact.file_type,
                ws=artifact.word_size,
            )

            # 2. Functions
            func_rows = [
                {
                    "address": f.address,
                    "name": f.name,
                    "size": f.size,
                    "decompiled_code": f.decompiled_code,
                    "binary_sha256": artifact.sha256,
                }
                for f in artifact.functions
            ]
            self._batch_unwind(
                session,
                func_rows,
                f"UNWIND $rows AS r "
                f"{op} (f:Function {{address: r.address, binary_sha256: r.binary_sha256}}) "
                "SET f.name = r.name, f.size = r.size, f.decompiled_code = r.decompiled_code "
                "WITH f, r "
                "MATCH (b:BinaryFile {sha256: r.binary_sha256}) "
                f"{op} (b)-[:DEFINES]->(f)",
                batch_size,
            )
            stats["functions"] = len(func_rows)

            # 3. Function CALLS relationships
            call_rows = []
            for f in artifact.functions:
                for callee_addr in f.callees:
                    call_rows.append(
                        {
                            "caller": f.address,
                            "callee": callee_addr,
                            "sha256": artifact.sha256,
                        }
                    )
            if call_rows:
                self._batch_unwind(
                    session,
                    call_rows,
                    "UNWIND $rows AS r "
                    "MATCH (caller:Function {address: r.caller, binary_sha256: r.sha256}) "
                    "MATCH (callee:Function {address: r.callee, binary_sha256: r.sha256}) "
                    f"{op} (caller)-[:CALLS]->(callee)",
                    batch_size,
                )
            stats["calls"] = len(call_rows)

            # 4. BasicBlocks
            bb_rows = []
            for f in artifact.functions:
                for bb in f.basic_blocks:
                    bb_rows.append(
                        {
                            "address": bb.address,
                            "size": bb.size,
                            "num_instructions": bb.num_instructions,
                            "binary_sha256": artifact.sha256,
                            "func_address": f.address,
                        }
                    )
            if bb_rows:
                self._batch_unwind(
                    session,
                    bb_rows,
                    "UNWIND $rows AS r "
                    f"{op} (bb:BasicBlock {{address: r.address, binary_sha256: r.binary_sha256}}) "
                    "SET bb.size = r.size, bb.num_instructions = r.num_instructions "
                    "WITH bb, r "
                    "MATCH (f:Function {address: r.func_address, binary_sha256: r.binary_sha256}) "
                    f"{op} (f)-[:CONTAINS]->(bb)",
                    batch_size,
                )
            stats["basic_blocks"] = len(bb_rows)

            # 5. FLOW_TO relationships between basic blocks
            flow_rows = []
            for f in artifact.functions:
                for bb in f.basic_blocks:
                    for succ in bb.successors:
                        flow_rows.append(
                            {
                                "source": bb.address,
                                "target": succ,
                                "sha256": artifact.sha256,
                            }
                        )
            if flow_rows:
                self._batch_unwind(
                    session,
                    flow_rows,
                    "UNWIND $rows AS r "
                    "MATCH (src:BasicBlock {address: r.source, binary_sha256: r.sha256}) "
                    "MATCH (tgt:BasicBlock {address: r.target, binary_sha256: r.sha256}) "
                    f"{op} (src)-[:FLOW_TO]->(tgt)",
                    batch_size,
                )
            stats["flows"] = len(flow_rows)

            # 6. Instructions
            insn_rows = []
            for f in artifact.functions:
                for bb in f.basic_blocks:
                    for insn in bb.instructions:
                        insn_rows.append(
                            {
                                "address": insn.address,
                                "mnemonic": insn.mnemonic,
                                "opcode": insn.opcode,
                                "category": insn.category,
                                "vex_ir": insn.vex_ir,
                                "binary_sha256": artifact.sha256,
                                "bb_address": bb.address,
                            }
                        )
            if insn_rows:
                self._batch_unwind(
                    session,
                    insn_rows,
                    "UNWIND $rows AS r "
                    f"{op} (i:Instruction {{address: r.address, binary_sha256: r.binary_sha256}}) "
                    "SET i.mnemonic = r.mnemonic, i.opcode = r.opcode, "
                    "i.category = r.category, i.vex_ir = r.vex_ir "
                    "WITH i, r "
                    "MATCH (bb:BasicBlock {address: r.bb_address, binary_sha256: r.binary_sha256}) "
                    f"{op} (bb)-[:CONTAINS]->(i)",
                    batch_size,
                )
            stats["instructions"] = len(insn_rows)

            # 7. Strings
            str_rows = []
            all_strings = set()
            for f in artifact.functions:
                for s in f.strings:
                    str_rows.append(
                        {
                            "value": s.value,
                            "address": s.address,
                            "sha256": artifact.sha256,
                            "func_address": f.address,
                        }
                    )
                    all_strings.add((s.value, s.address))
            # Also add global strings
            for s in artifact.strings:
                if (s.value, s.address) not in all_strings:
                    str_rows.append(
                        {
                            "value": s.value,
                            "address": s.address,
                            "sha256": artifact.sha256,
                            "func_address": None,
                        }
                    )
            if str_rows:
                # Create String nodes
                self._batch_unwind(
                    session,
                    str_rows,
                    "UNWIND $rows AS r "
                    f"{op} (s:String {{address: r.address, binary_sha256: r.sha256}}) "
                    "SET s.value = r.value",
                    batch_size,
                )
                # Link to functions
                func_str_rows = [r for r in str_rows if r["func_address"] is not None]
                if func_str_rows:
                    self._batch_unwind(
                        session,
                        func_str_rows,
                        "UNWIND $rows AS r "
                        "MATCH (f:Function {address: r.func_address, binary_sha256: r.sha256}) "
                        "MATCH (s:String {address: r.address, binary_sha256: r.sha256}) "
                        f"{op} (f)-[:REFERENCES_STRING]->(s)",
                        batch_size,
                    )
            stats["strings"] = len(str_rows)

            # 8. Imports
            imp_rows = []
            all_imports = set()
            for f in artifact.functions:
                for imp in f.imports:
                    imp_rows.append(
                        {
                            "name": imp.name,
                            "library": imp.library,
                            "address": imp.address,
                            "sha256": artifact.sha256,
                            "func_address": f.address,
                        }
                    )
                    all_imports.add((imp.name, imp.address))
            for imp in artifact.imports:
                if (imp.name, imp.address) not in all_imports:
                    imp_rows.append(
                        {
                            "name": imp.name,
                            "library": imp.library,
                            "address": imp.address,
                            "sha256": artifact.sha256,
                            "func_address": None,
                        }
                    )
            if imp_rows:
                self._batch_unwind(
                    session,
                    imp_rows,
                    "UNWIND $rows AS r "
                    f"{op} (i:Import {{address: r.address, binary_sha256: r.sha256}}) "
                    "SET i.name = r.name, i.library = r.library",
                    batch_size,
                )
                func_imp_rows = [r for r in imp_rows if r["func_address"] is not None]
                if func_imp_rows:
                    self._batch_unwind(
                        session,
                        func_imp_rows,
                        "UNWIND $rows AS r "
                        "MATCH (f:Function {address: r.func_address, binary_sha256: r.sha256}) "
                        "MATCH (i:Import {address: r.address, binary_sha256: r.sha256}) "
                        f"{op} (f)-[:REFERENCES_IMPORT]->(i)",
                        batch_size,
                    )
            stats["imports"] = len(imp_rows)

        log.info("binary_loaded", name=artifact.name, sha256=artifact.sha256[:12], stats=stats)
        return stats

    def clear_all(self) -> None:
        """Delete all nodes and relationships."""
        with self._driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
        log.info("graph_cleared")

    @staticmethod
    def _batch_unwind(
        session, rows: list[dict[str, Any]], query: str, batch_size: int
    ) -> None:
        """Execute a query in batches using UNWIND."""
        for i in range(0, len(rows), batch_size):
            batch = rows[i : i + batch_size]
            session.run(query, rows=batch)
