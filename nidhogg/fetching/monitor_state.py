"""Persisted progress marker for the PyPI changelog monitor."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

# Exceptions that indicate a failed state load (corrupt JSON, missing keys, etc.)
_LOAD_ERRORS = (OSError, ValueError, KeyError, TypeError)


@dataclass(frozen=True)
class MonitorState:
    """Persisted progress marker for ``nidhogg monitor``.

    Attributes:
        last_serial: The highest PyPI changelog serial processed so far.
    """

    last_serial: int


def load_state(index_file: Path) -> MonitorState | None:
    """Load the persisted monitor state, if any.

    Args:
        index_file: Path to the state JSON file.

    Returns:
        The persisted :class:`MonitorState`, or ``None`` if the file does
        not exist or cannot be parsed.
    """
    if not index_file.exists():
        return None
    try:
        data = json.loads(index_file.read_text(encoding="utf-8"))
        return MonitorState(last_serial=int(data["last_serial"]))
    except _LOAD_ERRORS:
        return None


def save_state(index_file: Path, state: MonitorState) -> None:
    """Persist *state* to *index_file*, creating parent directories as needed.

    Args:
        index_file: Path to the state JSON file.
        state: The state to persist.
    """
    index_file.parent.mkdir(parents=True, exist_ok=True)
    index_file.write_text(json.dumps(asdict(state)), encoding="utf-8")


def default_index_file() -> Path:
    """Return the default path for the monitor state file.

    Walks up from this module's location looking for ``pyproject.toml`` to
    find the project root. If found, returns
    ``<project_root>/.cache/nidhogg/monitor_state.json``.
    Falls back to ``~/.cache/nidhogg/monitor_state.json`` if the project root
    cannot be determined (e.g., when installed as a package).

    Returns:
        The default path for the monitor state file.
    """
    current = Path(__file__).resolve().parent
    for parent in [current, *current.parents]:
        if (parent / "pyproject.toml").exists():
            return parent / ".cache" / "nidhogg" / "monitor_state.json"
    return Path.home() / ".cache" / "nidhogg" / "monitor_state.json"
