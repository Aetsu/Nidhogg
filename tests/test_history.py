"""Tests for output/history.py."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from nidhogg.output.history import (
    append_binary_finding,
    append_finding,
    default_history_dir,
)

if TYPE_CHECKING:
    import pytest


def test_append_finding_creates_dated_file(tmp_path: Path):
    result = append_finding(tmp_path, {"package": {"name": "pkg"}})
    assert result is not None
    assert result.parent == tmp_path
    assert result.suffix == ".jsonl"


def test_append_finding_creates_missing_directory(tmp_path: Path):
    history_dir = tmp_path / "does" / "not" / "exist"
    result = append_finding(history_dir, {"package": {"name": "pkg"}})
    assert result is not None
    assert result.exists()


def test_append_finding_accumulates_across_calls(tmp_path: Path):
    append_finding(tmp_path, {"package": {"name": "a"}})
    result = append_finding(tmp_path, {"package": {"name": "b"}})
    assert result is not None
    lines = result.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["package"]["name"] == "a"
    assert json.loads(lines[1])["package"]["name"] == "b"


def test_append_finding_returns_none_on_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def _boom(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(Path, "open", _boom)
    result = append_finding(tmp_path, {"package": {"name": "pkg"}})
    assert result is None


def test_append_finding_stamps_analyzed_at(tmp_path: Path):
    result = append_finding(tmp_path, {"package": {"name": "pkg"}})
    assert result is not None
    line = json.loads(result.read_text(encoding="utf-8").splitlines()[0])
    assert "analyzed_at" in line


def test_default_history_dir_returns_project_cache_path():
    result = default_history_dir()
    assert result.parts[-3:] == (".cache", "nidhogg", "history")


def test_default_history_dir_uses_project_root_with_pyproject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    import nidhogg.output.history as history_module

    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "pyproject.toml").touch()
    fake_module_file = project_root / "nidhogg" / "output" / "history.py"
    fake_module_file.parent.mkdir(parents=True)
    fake_module_file.touch()

    monkeypatch.setattr(history_module, "__file__", str(fake_module_file))

    result = default_history_dir()
    assert result == project_root / ".cache" / "nidhogg" / "history"


def test_default_history_dir_falls_back_to_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    import nidhogg.output.history as history_module

    fake_module_file = tmp_path / "nidhogg" / "output" / "history.py"
    fake_module_file.parent.mkdir(parents=True)
    fake_module_file.touch()

    monkeypatch.setattr(history_module, "__file__", str(fake_module_file))

    result = default_history_dir()
    assert result == Path.home() / ".cache" / "nidhogg" / "history"


def test_append_binary_finding_creates_dated_file_under_binaries_subdir(
    tmp_path: Path,
):
    result = append_binary_finding(tmp_path, {"package": {"name": "pkg"}})
    assert result is not None
    assert result.parent == tmp_path / "binaries"
    assert result.suffix == ".jsonl"


def test_append_binary_finding_does_not_touch_url_history_file(tmp_path: Path):
    append_binary_finding(tmp_path, {"package": {"name": "pkg"}})
    assert list(tmp_path.glob("*.jsonl")) == []


def test_append_binary_finding_accumulates_across_calls(tmp_path: Path):
    append_binary_finding(tmp_path, {"package": {"name": "a"}})
    result = append_binary_finding(tmp_path, {"package": {"name": "b"}})
    assert result is not None
    lines = result.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2


def test_append_binary_finding_stamps_analyzed_at(tmp_path: Path):
    result = append_binary_finding(tmp_path, {"package": {"name": "pkg"}})
    assert result is not None
    line = json.loads(result.read_text(encoding="utf-8").splitlines()[0])
    assert "analyzed_at" in line


def test_append_binary_finding_returns_none_on_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def _boom(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(Path, "open", _boom)
    result = append_binary_finding(tmp_path, {"package": {"name": "pkg"}})
    assert result is None
