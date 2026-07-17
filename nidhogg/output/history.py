"""Append-only JSONL history log for analysis results."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger


def append_finding(history_dir: Path, document: dict[str, object]) -> Path | None:
    """Append *document* to today's JSONL history file under *history_dir*.

    Args:
        history_dir: Directory to store dated history files in. Created if
            it does not exist.
        document: The result document to append (e.g. from ``build_document``).

    Returns:
        The path written to, or ``None`` if the write failed (permissions,
        disk full, ...) — logged as a warning, never raised.
    """
    now = datetime.now(UTC)
    file_path = history_dir / f"{now.date().isoformat()}.jsonl"
    stamped = {"analyzed_at": now.isoformat(), **document}
    try:
        history_dir.mkdir(parents=True, exist_ok=True)
        with file_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(stamped, default=str) + "\n")
    except OSError as exc:
        logger.warning("Could not write history file {}: {}", file_path, exc)
        return None
    return file_path


def default_history_dir() -> Path:
    """Return the default directory for history JSONL files.

    Walks up from this module's location looking for ``pyproject.toml`` to
    find the project root. If found, returns
    ``<project_root>/.cache/nidhogg/history``. Falls back to
    ``~/.cache/nidhogg/history`` if the project root cannot be determined
    (e.g., when installed as a package).

    Returns:
        The default directory for history JSONL files.
    """
    current = Path(__file__).resolve().parent
    for parent in [current, *current.parents]:
        if (parent / "pyproject.toml").exists():
            return parent / ".cache" / "nidhogg" / "history"
    return Path.home() / ".cache" / "nidhogg" / "history"
