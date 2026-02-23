"""revgraph llm — LLM-powered analysis tasks."""

from __future__ import annotations

from typing import Optional

import typer

llm_app = typer.Typer(no_args_is_help=True)


@llm_app.command()
def summarize(
    target: str = typer.Argument(..., help="Function address or binary SHA256"),
    scope: str = typer.Option("function", "--scope", help="function|binary"),
    write_to_graph: bool = typer.Option(False, "--write-to-graph", help="Store summary in Neo4j"),
) -> None:
    """Summarize a function or entire binary using LLM."""
    from revgraph.cli.app import get_context
    from revgraph.llm.summarizer import Summarizer
    from revgraph.utils.formatters import console, print_success

    ctx = get_context()
    driver = ctx.ensure_neo4j()
    llm = ctx.ensure_llm()

    summarizer = Summarizer(llm, driver)
    result = summarizer.summarize(target, scope=scope)

    console.print(f"\n[bold]Summary ({scope}):[/bold]\n{result['summary']}\n")

    if write_to_graph:
        summarizer.write_summary(target, result["summary"], scope=scope)
        print_success("Summary written to graph")


@llm_app.command()
def label(
    sha256: str = typer.Argument(..., help="Binary SHA256"),
    confidence_threshold: float = typer.Option(0.7, "--confidence-threshold", help="Min confidence"),
    write_to_graph: bool = typer.Option(False, "--write-to-graph", help="Store labels in Neo4j"),
) -> None:
    """Label functions with descriptive names using LLM."""
    from revgraph.cli.app import get_context
    from revgraph.llm.labeler import FunctionLabeler
    from revgraph.utils.formatters import print_table, print_success

    ctx = get_context()
    driver = ctx.ensure_neo4j()
    llm = ctx.ensure_llm()

    labeler = FunctionLabeler(llm, driver)
    results = labeler.label_functions(sha256, confidence_threshold=confidence_threshold)

    rows = [
        {
            "address": r["address"],
            "original": r["original_name"],
            "label": r["label"],
            "confidence": f"{r['confidence']:.2f}",
        }
        for r in results
    ]
    print_table(rows, title="Function Labels")

    if write_to_graph:
        labeler.write_labels(sha256, results)
        print_success(f"Wrote {len(results)} labels to graph")


@llm_app.command(name="vuln-report")
def vuln_report(
    sha256: str = typer.Argument(..., help="Binary SHA256"),
    format: str = typer.Option("markdown", "--format", "-f", help="markdown|json"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Generate a vulnerability report for a binary."""
    from revgraph.cli.app import get_context
    from revgraph.llm.vuln_reporter import VulnReporter
    from revgraph.utils.formatters import console, print_success

    ctx = get_context()
    driver = ctx.ensure_neo4j()
    llm = ctx.ensure_llm()

    reporter = VulnReporter(llm, driver)
    report = reporter.generate_report(sha256, output_format=format)

    if output:
        from pathlib import Path

        Path(output).write_text(report)
        print_success(f"Report written to {output}")
    else:
        console.print(report)


@llm_app.command(name="exploit-analyze")
def exploit_analyze(
    binary: str = typer.Argument(..., help="Path to ELF binary or binary SHA256"),
    libc: Optional[str] = typer.Option(None, "--libc", help="Path to libc.so"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output JSON file"),
) -> None:
    """Multi-pass exploit analysis: identify → validate → chain."""
    import subprocess
    from pathlib import Path

    from revgraph.cli.app import get_context
    from revgraph.llm.exploit_analyzer import ExploitAnalyzer
    from revgraph.utils.formatters import console

    ctx = get_context()
    llm = ctx.ensure_llm()

    # Try agentic mode if graph is available and binary looks like a SHA256
    sha256: str | None = None
    registry = None
    if len(binary) == 64 and all(c in "0123456789abcdef" for c in binary.lower()):
        # Treat as SHA256 — try agentic mode
        try:
            driver = ctx.ensure_neo4j()
            from revgraph.agents.registry import ToolRegistry

            registry = ToolRegistry(driver, llm)
            sha256 = binary
        except Exception:
            pass  # Fall through to stuffed mode

    binary_path = Path(binary)
    if sha256 is None and not binary_path.exists():
        console.print(f"[red]Binary not found: {binary}[/red]")
        raise typer.Exit(1)

    # Gather binary metadata
    if sha256 and registry:
        # Agentic mode — model will fetch data via tools
        file_out = ""
        checksec_out = ""
        disassembly = ""
        strings_list: list[str] = []
        arch = "unknown"
        libc_version = "unknown"
    else:
        file_out = subprocess.run(
            ["file", str(binary_path)], capture_output=True, text=True
        ).stdout.strip()

        checksec_out = ""
        try:
            checksec_out = subprocess.run(
                ["checksec", "--file", str(binary_path)],
                capture_output=True, text=True,
            ).stdout.strip()
        except FileNotFoundError:
            checksec_out = "checksec not available"

        # Get disassembly of user-defined functions
        objdump = subprocess.run(
            ["objdump", "-d", str(binary_path)], capture_output=True, text=True,
        )
        disasm_lines = objdump.stdout.splitlines()
        # Filter to user functions (skip _start, __libc, deregister, register, etc.)
        skip_prefixes = (
            "_start", "_init", "_fini", "_dl_", "__do_global", "__libc_csu",
            "deregister_tm", "register_tm", "frame_dummy", "__do_global",
            ".plt", "<.plt",
        )
        filtered = []
        include = False
        for line in disasm_lines:
            if line.strip().endswith(">:"):
                func_name = line.split("<")[1].split(">")[0] if "<" in line else ""
                include = not any(func_name.startswith(p) for p in skip_prefixes)
            if include:
                filtered.append(line)
        disassembly = "\n".join(filtered)

        # Strings
        strings_out = subprocess.run(
            ["strings", str(binary_path)], capture_output=True, text=True,
        )
        strings_list = [s for s in strings_out.stdout.splitlines() if len(s) > 3][:50]

        # Libc version
        libc_version = "unknown"
        if libc:
            libc_strings = subprocess.run(
                ["strings", libc], capture_output=True, text=True,
            )
            for line in libc_strings.stdout.splitlines():
                if "GNU C Library" in line:
                    libc_version = line.strip()
                    break

        # Architecture from file output
        arch = "x86-64" if "x86-64" in file_out else "unknown"

    console.print("[bold]Pass 1/3:[/bold] Identifying vulnerabilities...")
    analyzer = ExploitAnalyzer(llm, sha256=sha256, registry=registry)
    result = analyzer.analyze(
        name=binary_path.name if not sha256 else sha256[:12],
        architecture=arch,
        protections=checksec_out,
        libc_version=libc_version,
        disassembly=disassembly,
        strings=strings_list,
    )

    # Print summary
    n_id = len(result["identified"])
    n_confirmed = sum(1 for v in result["validated"] if v.get("confirmed"))
    n_killed = sum(1 for v in result["validated"] if not v.get("confirmed"))

    console.print(f"\n[bold]Results:[/bold]")
    console.print(f"  Identified:  {n_id} potential vulnerabilities")
    console.print(f"  Confirmed:   {n_confirmed}")
    console.print(f"  Killed:      {n_killed}")

    for v in result["validated"]:
        status = "[green]CONFIRMED[/green]" if v.get("confirmed") else "[red]KILLED[/red]"
        console.print(f"  {status} {v.get('id', '?')}: {v.get('primitive') or v.get('kill_reason', '')}")

    chain = result["chain"]
    if chain.get("feasible"):
        console.print(f"\n[bold green]Exploit feasible:[/bold green] {chain.get('strategy', '')}")
        for step in chain.get("steps", []):
            console.print(f"  Step {step.get('step')}: {step.get('action')}")
        if chain.get("exploit_skeleton"):
            console.print(f"\n[bold]Exploit skeleton:[/bold]")
            console.print(chain["exploit_skeleton"])
    else:
        console.print(f"\n[bold yellow]Exploit not feasible with confirmed vulns.[/bold yellow]")
        if chain.get("missing_primitive"):
            console.print(f"  Missing: {chain['missing_primitive']}")

    if output:
        import json
        Path(output).write_text(json.dumps(result, indent=2))
        console.print(f"\nFull results written to {output}")


@llm_app.command()
def yara(
    sha256: str = typer.Argument(..., help="Binary SHA256"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output .yar file"),
) -> None:
    """Generate YARA rules for a binary."""
    from revgraph.cli.app import get_context
    from revgraph.llm.yara_generator import YARAGenerator
    from revgraph.utils.formatters import console, print_success

    ctx = get_context()
    driver = ctx.ensure_neo4j()
    llm = ctx.ensure_llm()

    generator = YARAGenerator(llm, driver)
    rules = generator.generate(sha256)

    if output:
        from pathlib import Path

        Path(output).write_text(rules)
        print_success(f"YARA rules written to {output}")
    else:
        console.print(rules)
