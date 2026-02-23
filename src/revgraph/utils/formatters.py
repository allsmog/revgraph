"""Rich output formatters for CLI display."""

from __future__ import annotations

import json
from typing import Any, Sequence

from rich.console import Console
from rich.table import Table

console = Console()
err_console = Console(stderr=True)


def print_table(
    rows: Sequence[dict[str, Any]],
    title: str | None = None,
    columns: Sequence[str] | None = None,
) -> None:
    """Render a list of dicts as a Rich table."""
    if not rows:
        console.print("[dim]No results.[/dim]")
        return

    cols = columns or list(rows[0].keys())
    table = Table(title=title, show_lines=True)
    for col in cols:
        table.add_column(col, overflow="fold")

    for row in rows:
        table.add_row(*(str(row.get(c, "")) for c in cols))

    console.print(table)


def print_json(data: Any) -> None:
    console.print_json(json.dumps(data, default=str, indent=2))


def print_success(msg: str) -> None:
    console.print(f"[bold green]{msg}[/bold green]")


def print_error(msg: str) -> None:
    err_console.print(f"[bold red]Error:[/bold red] {msg}")


def print_warning(msg: str) -> None:
    err_console.print(f"[bold yellow]Warning:[/bold yellow] {msg}")
