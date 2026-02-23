"""revgraph analyze-bin — standalone binary analysis (no Ghidra, no Neo4j)."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer


def analyze_bin_cmd(
    binary: Path = typer.Argument(..., help="Path to ELF binary"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="LLM model override"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write report to file"),
) -> None:
    """Analyze a raw ELF binary end-to-end using the LLM backend."""
    from revgraph.cli.app import get_context
    from revgraph.extraction.elf_loader import load_elf
    from revgraph.llm.prompts import SUMMARIZE_FUNCTION, VULN_REPORT
    from revgraph.utils.formatters import console, print_error, print_success

    if not binary.exists():
        print_error(f"File not found: {binary}")
        raise typer.Exit(1)

    # 1. Extract
    console.print(f"[bold]Extracting:[/bold] {binary}")
    artifact = load_elf(binary)
    if artifact is None:
        print_error("Failed to parse ELF binary.")
        raise typer.Exit(1)

    console.print(
        f"  arch={artifact.architecture} | functions={len(artifact.functions)} | "
        f"strings={len(artifact.strings)} | imports={len(artifact.imports)}"
    )

    # 2. Get LLM client
    ctx = get_context()
    if model:
        ctx.model_override = model
    llm = ctx.ensure_llm()

    # Dangerous API patterns for vuln detection
    DANGEROUS_APIS = {
        "strcpy", "strcat", "sprintf", "gets", "scanf", "system",
        "exec", "execve", "popen", "dlopen", "mmap", "mprotect",
        "chmod", "chown", "setuid", "setgid", "ptrace",
    }

    # 3. Summarize each function
    console.print(f"\n[bold]Analyzing {len(artifact.functions)} function(s)...[/bold]\n")
    summaries: list[str] = []
    dangerous_functions: list[dict] = []

    for func in artifact.functions:
        # Build disassembly listing
        asm_lines = []
        for block in func.basic_blocks:
            for insn in block.instructions:
                asm_lines.append(f"  {hex(insn.address)}: {insn.mnemonic} {insn.opcode}")
        asm_text = "\n".join(asm_lines[:60])  # Cap at 60 lines

        string_vals = [s.value for s in func.strings]
        import_names = [i.name for i in func.imports]
        callee_names = []
        for caddr in func.callees:
            for f2 in artifact.functions:
                if f2.address == caddr:
                    callee_names.append(f2.name)
                    break
            else:
                # Check imports
                for imp in artifact.imports:
                    if imp.address == caddr:
                        callee_names.append(imp.name)
                        break

        prompt = SUMMARIZE_FUNCTION.render(
            name=func.name,
            address=hex(func.address),
            decompiled_code=asm_text,
            strings=string_vals,
            imports=import_names,
            callers=[],
            callees=callee_names,
        )

        console.print(f"  [cyan]{func.name}[/cyan] @ {hex(func.address)} ({func.size} bytes, {len(func.imports)} imports)")
        summary = llm.complete(
            messages=[{"role": "user", "content": prompt}],
        )
        summaries.append(f"### {func.name} ({hex(func.address)})\n{summary}\n")
        console.print(f"    {summary[:120]}...")

        # Track dangerous API usage
        dangerous_in_func = [i for i in import_names if i.rstrip("@plt") in DANGEROUS_APIS]
        if dangerous_in_func:
            dangerous_functions.append({
                "name": func.name,
                "dangerous_imports": dangerous_in_func,
                "decompiled_code": asm_text,
            })

    # 4. Overall vuln report
    console.print(f"\n[bold]Generating vulnerability report...[/bold]")
    all_strings = [s.value for s in artifact.strings]
    high_bbr = [{"name": f.name, "bbr_score": f.size} for f in sorted(artifact.functions, key=lambda x: x.size, reverse=True)[:5]]

    vuln_prompt = VULN_REPORT.render(
        name=artifact.name,
        architecture=artifact.architecture,
        dangerous_functions=dangerous_functions,
        high_bbr_functions=high_bbr,
        format="markdown",
    )
    vuln_report_text = llm.complete(
        messages=[{"role": "user", "content": vuln_prompt}],
    )

    # 5. Assemble full report
    report = f"# RevGraph Analysis: {artifact.name}\n\n"
    report += f"**SHA256:** `{artifact.sha256}`\n"
    report += f"**Architecture:** {artifact.architecture} ({artifact.word_size}-bit, {artifact.endianness})\n"
    report += f"**Type:** {artifact.file_type}\n"
    report += f"**Functions:** {len(artifact.functions)}\n"
    report += f"**Strings:** {len(artifact.strings)}\n"
    report += f"**Imports:** {', '.join(i.name for i in artifact.imports)}\n\n"
    report += "## Function Summaries\n\n"
    report += "\n".join(summaries)
    report += "\n## Vulnerability Assessment\n\n"
    report += vuln_report_text
    report += "\n"

    if output:
        Path(output).write_text(report)
        print_success(f"Report written to {output}")
    else:
        console.print("\n" + report)
