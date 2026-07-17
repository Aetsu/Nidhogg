"""Tests for fetching/monitor_state.py."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from nidhogg.fetching.monitor_state import (
    MonitorState,
    default_index_file,
    load_state,
    save_state,
)

if TYPE_CHECKING:
    import pytest


def test_load_state_returns_none_when_file_missing(tmp_path: Path):
    assert load_state(tmp_path / "missing.json") is None


def test_save_then_load_round_trips(tmp_path: Path):
    index_file = tmp_path / "state.json"
    save_state(index_file, MonitorState(last_serial=12345))
    loaded = load_state(index_file)
    assert loaded == MonitorState(last_serial=12345)


def test_save_state_creates_parent_directories(tmp_path: Path):
    index_file = tmp_path / "a" / "b" / "state.json"
    save_state(index_file, MonitorState(last_serial=1))
    assert index_file.exists()


def test_load_state_returns_none_on_corrupt_json(tmp_path: Path):
    index_file = tmp_path / "state.json"
    index_file.write_text("not json", encoding="utf-8")
    assert load_state(index_file) is None


def test_default_index_file_returns_project_cache_path():
    result = default_index_file()
    assert result.parts[-3:] == (".cache", "nidhogg", "monitor_state.json")


def test_default_index_file_uses_project_root_with_pyproject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    import nidhogg.fetching.monitor_state as monitor_state_module

    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "pyproject.toml").touch()
    fake_module_file = project_root / "nidhogg" / "fetching" / "monitor_state.py"
    fake_module_file.parent.mkdir(parents=True)
    fake_module_file.touch()

    monkeypatch.setattr(monitor_state_module, "__file__", str(fake_module_file))

    result = default_index_file()
    assert result == project_root / ".cache" / "nidhogg" / "monitor_state.json"


def test_default_index_file_falls_back_to_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    import nidhogg.fetching.monitor_state as monitor_state_module

    fake_module_file = tmp_path / "nidhogg" / "fetching" / "monitor_state.py"
    fake_module_file.parent.mkdir(parents=True)
    fake_module_file.touch()

    monkeypatch.setattr(monitor_state_module, "__file__", str(fake_module_file))

    result = default_index_file()
    assert result == Path.home() / ".cache" / "nidhogg" / "monitor_state.json"
