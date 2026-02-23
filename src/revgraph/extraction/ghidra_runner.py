"""Optional headless Ghidra automation for BCC extraction."""

from __future__ import annotations

import subprocess
from pathlib import Path

from revgraph.utils.logging import get_logger

log = get_logger(__name__)

DEFAULT_GHIDRA_HOME = "/opt/ghidra"
ANALYZE_HEADLESS = "analyzeHeadless"


def run_ghidra_headless(
    binary_path: Path,
    output_dir: Path,
    ghidra_home: str | None = None,
    script_name: str = "ExportBCC.java",
    extra_args: list[str] | None = None,
) -> Path | None:
    """Run Ghidra in headless mode to produce a .bcc file.

    Requires Ghidra + Blackfyre plugin to be installed.
    """
    ghidra = Path(ghidra_home or DEFAULT_GHIDRA_HOME)
    headless = ghidra / "support" / ANALYZE_HEADLESS

    if not headless.exists():
        log.error("ghidra_not_found", path=str(headless))
        return None

    project_dir = output_dir / ".ghidra_project"
    project_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(headless),
        str(project_dir),
        "revgraph_temp",
        "-import",
        str(binary_path),
        "-postScript",
        script_name,
        str(output_dir),
        "-deleteProject",
    ]
    if extra_args:
        cmd.extend(extra_args)

    log.info("running_ghidra", cmd=" ".join(cmd))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            log.error("ghidra_failed", stderr=result.stderr[:500])
            return None
    except subprocess.TimeoutExpired:
        log.error("ghidra_timeout")
        return None

    expected_bcc = output_dir / f"{binary_path.stem}.bcc"
    if expected_bcc.exists():
        log.info("ghidra_success", output=str(expected_bcc))
        return expected_bcc

    # Search for any .bcc produced
    bcc_files = list(output_dir.glob("*.bcc"))
    if bcc_files:
        return bcc_files[0]

    log.error("no_bcc_produced")
    return None
