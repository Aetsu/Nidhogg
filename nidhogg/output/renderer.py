"""Rich-based human presentation for Nidhogg CLI output.

This module returns rich renderables (Text, Table, Group, Progress) consumed by
``cli.py`` through a single shared ``Console``. JSON serialization lives in
``writer.py``; this module never emits JSON.
"""

from __future__ import annotations

import sys
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, TextIO

from rich.console import Console, Group, RenderableType
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from nidhogg.core.models import FileAnalysis, PackageAnalysis


def make_console(stream: TextIO | None = None) -> Console:
    """Build the shared CLI console.

    When *stream* is a terminal, colors are emitted; otherwise (pipes, files,
    CI) ``color_system`` is ``None`` so rich prints plain text with no ANSI
    escapes.

    Args:
        stream: Output stream; defaults to ``sys.stdout``.

    Returns:
        A configured ``rich.console.Console``.
    """
    stream = stream or sys.stdout
    is_tty = getattr(stream, "isatty", lambda: False)()
    return Console(
        file=stream,
        force_terminal=is_tty,
        color_system="auto" if is_tty else None,
        highlight=False,
    )


def render_empty(
    analysis: PackageAnalysis,
    *,
    display_name: str | None = None,
) -> Text:
    """Render the green one-liner shown when a package has no URL findings.

    Args:
        analysis: Completed package analysis.
        display_name: Override the package name in the output.

    Returns:
        A green ``Text`` like ``"● name: no URLs found"``.
    """
    name = display_name or analysis.name
    return Text(f"● {name}: no URLs found", style="green")


def _http_status_style(status: int) -> str:
    """Return the rich style for an HTTP status code by response class.

    Args:
        status: HTTP status code.

    Returns:
        A rich style string.
    """
    if 200 <= status < 300:  # noqa: PLR2004
        return "green"
    if 300 <= status < 400:  # noqa: PLR2004
        return "yellow"
    if 400 <= status < 600:  # noqa: PLR2004
        return "red"
    return "dim"


def render_file_block(file_analysis: FileAnalysis, pkg_path: Path) -> Group:
    """Render one file's header (path + file tags) and its findings table.

    Args:
        file_analysis: The per-file analysis to render.
        pkg_path: Package root used to relativise the file path.

    Returns:
        A ``Group`` with a header line and a borderless findings table.
    """
    try:
        rel = str(file_analysis.filepath.relative_to(pkg_path))
    except ValueError:
        rel = str(file_analysis.filepath)

    header = Text()
    header.append(rel, style="bold")
    for tag in sorted(t.value for t in file_analysis.tags):
        header.append(f" [{tag}]", style="cyan")

    table = Table(box=None, show_header=False, pad_edge=False, expand=False)
    table.add_column("LOC", no_wrap=True)
    table.add_column("Layer", no_wrap=True)
    table.add_column("URL")
    for f in sorted(file_analysis.findings, key=lambda x: (x.layer.value, x.value)):
        loc = Text(str(f.lineno))
        layer = Text(f.layer.value, style="dim")
        url = Text(f.value)
        if f.cert_issuer is not None and "Let's Encrypt" in f.cert_issuer:
            url.append(" [LE]", style="yellow")
        if f.http_status is not None:
            url.append(f" [{f.http_status}]", style=_http_status_style(f.http_status))
        if f.http_title is not None:
            url.append(f" {f.http_title}", style="dim")
        for tag in sorted(t.value for t in f.tags):
            url.append(f" [{tag.upper()}]", style="bold red")
        table.add_row(loc, layer, url)

    return Group(header, table)


def render_package_header(name: str) -> Text:
    """Render the per-package header used in batch and monitor output.

    Args:
        name: Package display name.

    Returns:
        A ``Text`` like ``"── evilpkg"``.
    """
    line = Text()
    line.append(f"── {name}", style="bold")
    return line


def render_package_result(
    analysis: PackageAnalysis,
    *,
    display_name: str | None = None,
) -> Group | Text:
    """Render the full human-readable block for one package.

    When there are no findings, delegates to :func:`render_empty`. Otherwise
    returns a ``Group`` of a package summary and one block per file that has
    findings.

    Args:
        analysis: Completed package analysis.
        display_name: Override the package name in the header.

    Returns:
        A ``Group`` of renderables, or a ``Text`` for the empty case.
    """
    if not analysis.findings:
        return render_empty(analysis, display_name=display_name)

    name = display_name or analysis.name
    blocks: list[RenderableType] = [
        Text("package  ").append(name, style="bold"),
        Text("path     ").append(str(analysis.path), style="dim"),
        Text(""),
        Text(f"findings {len(analysis.findings)}"),
        Text(""),
    ]
    for fa in analysis.files:
        if fa.findings:
            blocks.append(render_file_block(fa, analysis.path))
            blocks.append(Text(""))
    return Group(*blocks)


def render_progress(*, console: Console) -> Progress:
    """Build the shared progress display used by the monitor.

    Columns: spinner, description, bar, M-of-N, elapsed. The caller is
    responsible for ``add_task(description, total=...)`` and ``advance``.

    Args:
        console: Console to render into.

    Returns:
        A ``rich.progress.Progress`` the caller enters with ``with``.
    """
    return Progress(
        SpinnerColumn(),
        "{task.description}",
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    )


@contextmanager
def render_status(message: str, *, console: Console) -> Iterator[None]:
    """Wrap ``console.status(message)`` as a context manager.

    Args:
        message: Status text.
        console: Console to show the spinner on.

    Yields:
        None for the duration of the status.
    """
    with console.status(message):
        yield


def render_countdown(interval: int, *, console: Console) -> None:
    """Sleep for *interval* seconds showing a live countdown spinner.

    Always sleeps at least once, even for ``interval <= 0``, so callers that
    patch ``time.sleep`` to raise ``KeyboardInterrupt`` keep working.

    Args:
        interval: Seconds to wait.
        console: Console to render the spinner on.
    """
    if interval <= 0:
        time.sleep(interval)
        return

    remaining = interval
    with Progress(SpinnerColumn(), "{task.description}", console=console) as progress:
        task_id = progress.add_task(
            f"Esperando nuevos paquetes... próxima comprobación en {remaining}s"
        )
        while remaining > 0:
            time.sleep(1)
            remaining -= 1
            progress.update(
                task_id,
                description=(
                    f"Esperando nuevos paquetes... próxima comprobación en {remaining}s"
                ),
            )
