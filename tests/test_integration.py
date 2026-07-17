"""Integration tests: full pipeline over tests/fixtures/pkg_malicioso/."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from nidhogg.analysis.aggregator import aggregate
from nidhogg.analysis.walker import analyze_package
from nidhogg.output.writer import write_results

PKG = Path(__file__).parent / "fixtures" / "pkg_malicioso"


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def test_pipeline_produces_findings():
    analysis = analyze_package(PKG)
    analysis.files = aggregate(analysis.files)
    assert len(analysis.findings) > 0


def test_pipeline_finds_c2_url():
    analysis = analyze_package(PKG)
    analysis.files = aggregate(analysis.files)
    urls = {f.value for f in analysis.findings}
    assert any("pastebin.com" in url for url in urls)


def test_pipeline_finds_beacon_url():
    analysis = analyze_package(PKG)
    analysis.files = aggregate(analysis.files)
    urls = {f.value for f in analysis.findings}
    assert any("beacon" in url for url in urls)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def test_pipeline_output_structure(tmp_path: Path):
    analysis = analyze_package(PKG)
    analysis.files = aggregate(analysis.files)
    out = tmp_path / "results.json"
    write_results(analysis, out)
    data = json.loads(out.read_text())
    assert "package" in data
    assert "summary" in data
    assert "files" in data


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_exits_zero_for_analyzed_package():
    from nidhogg.cli import _run_analyze

    code = _run_analyze(PKG, None, as_json=False, verbose=False)
    assert code == 0


def test_cli_prints_json_to_stdout(capsys: pytest.CaptureFixture[str]):
    from nidhogg.cli import _run_analyze

    _run_analyze(PKG, None, as_json=True, verbose=False)
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "files" in data


def test_cli_pretty_output_to_stdout(capsys: pytest.CaptureFixture[str]):
    from nidhogg.cli import _run_analyze

    _run_analyze(PKG, None, as_json=False, verbose=False)
    captured = capsys.readouterr()
    assert "pastebin.com" in captured.out


def test_cli_writes_file_when_output_given(tmp_path: Path):
    from nidhogg.cli import _run_analyze

    out = tmp_path / "results.json"
    _run_analyze(PKG, out, as_json=False, verbose=False)
    assert out.exists()
    data = json.loads(out.read_text())
    assert "files" in data


def test_cli_main_analyze_command(tmp_path: Path):
    from nidhogg.cli import main

    out = tmp_path / "results.json"
    with (
        patch.object(
            sys, "argv", ["nidhogg", "analyze", str(PKG), "--output", str(out)]
        ),
        pytest.raises(SystemExit) as exc_info,
    ):
        main()
    assert exc_info.value.code == 0
    assert out.exists()


def test_cli_exits_zero_for_clean_package(tmp_path: Path):
    from nidhogg.cli import _run_analyze

    clean = tmp_path / "clean_pkg"
    clean.mkdir()
    (clean / "hello.py").write_text('print("hello world")\n', encoding="utf-8")
    code = _run_analyze(clean, None, as_json=False, verbose=False)
    assert code == 0


def test_cli_error_on_missing_path(tmp_path: Path):
    from nidhogg.cli import _run_analyze

    code = _run_analyze(tmp_path / "nonexistent", None, as_json=False, verbose=False)
    assert code == 2


def test_analyze_json_output_has_files_section(capsys) -> None:
    from nidhogg.cli import _run_analyze

    root = Path(__file__).parent / "fixtures" / "pkg_malicioso"
    rc = _run_analyze(root, None, as_json=True, verbose=False)
    assert rc == 0
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert "files" in doc
    assert "total_files" in doc["summary"]
