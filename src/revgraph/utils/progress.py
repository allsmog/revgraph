"""Rich progress bar utilities."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)


def create_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
    )


@contextmanager
def progress_context(description: str, total: int) -> Generator[tuple[Progress, int], None, None]:
    """Context manager yielding (progress, task_id) for a single tracked task."""
    progress = create_progress()
    with progress:
        task_id = progress.add_task(description, total=total)
        yield progress, task_id
