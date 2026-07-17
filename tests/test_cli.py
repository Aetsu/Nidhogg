"""Tests for cli.py's pipeline wiring."""

from __future__ import annotations

import json
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import nidhogg.output.history as history_module
from nidhogg.cli import (
    _analyse_new_package,
    _build_parser,
    _initial_backfill_serial,
    _run_analyze,
    _run_fetch,
    _run_monitor,
    main,
)
from nidhogg.core.exceptions import PackageReadError
from nidhogg.core.models import (
    AnalysisLayer,
    FileAnalysis,
    PackageAnalysis,
    UrlFinding,
)
from nidhogg.fetching.changelog import ChangelogEntry
from nidhogg.fetching.monitor_state import MonitorState, load_state, save_state


def test_build_parser_history_dir_defaults_none():
    parser = _build_parser()
    args = parser.parse_args(["analyze", "some/path"])
    assert args.history_dir is None


def test_build_parser_history_dir_accepts_path():
    parser = _build_parser()
    args = parser.parse_args(
        ["analyze", "some/path", "--history-dir", "/tmp/hist"]  # noqa: S108
    )
    assert str(args.history_dir) == "/tmp/hist"  # noqa: S108


def test_build_parser_once_defaults_false():
    parser = _build_parser()
    args = parser.parse_args(["monitor"])
    assert args.once is False


def test_build_parser_once_flag_sets_true():
    parser = _build_parser()
    args = parser.parse_args(["monitor", "--once"])
    assert args.once is True


def test_main_analyze_uses_default_history_dir_when_omitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    default_dir = tmp_path / "default-history"

    monkeypatch.setattr(history_module, "default_history_dir", lambda: default_dir)
    monkeypatch.setattr(sys, "argv", ["nidhogg", "analyze", str(pkg_dir)])

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 0
    assert len(list(default_dir.glob("*.jsonl"))) == 1


def test_run_analyze_appends_to_history(tmp_path: Path):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    history_dir = tmp_path / "history"
    exit_code = _run_analyze(
        pkg_dir,
        None,
        as_json=False,
        verbose=False,
        history_dir=history_dir,
    )
    assert exit_code == 0
    assert len(list(history_dir.glob("*.jsonl"))) == 1


def test_run_analyze_no_history_dir_writes_nothing(tmp_path: Path):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    exit_code = _run_analyze(pkg_dir, None, as_json=False, verbose=False)
    assert exit_code == 0
    assert list(tmp_path.glob("*.jsonl")) == []


def test_run_fetch_analyses_downloaded_package(tmp_path: Path):
    extracted = tmp_path / "extracted"
    (extracted / "pkg").mkdir(parents=True)
    (extracted / "pkg" / "module.py").write_text("x = 1", encoding="utf-8")

    @contextmanager
    def _fake_fetched_package(
        name,  # noqa: ARG001
        version=None,  # noqa: ARG001
        *,
        keep=False,  # noqa: ARG001
        keep_dir=None,  # noqa: ARG001
    ):
        yield extracted, "1.0", "https://example.com/pkg-1.0.tar.gz"

    output = tmp_path / "result.json"
    with patch("nidhogg.fetching.pypi_fetch.fetched_package", _fake_fetched_package):
        exit_code = _run_fetch(
            "somepkg",
            None,
            output,
            as_json=False,
            verbose=False,
            keep_download=None,
            history_dir=None,
        )
    assert exit_code == 0
    document = json.loads(output.read_text())
    assert document["package"]["name"] == "somepkg"
    assert document["package"]["version"] == "1.0"
    assert document["package"]["download_url"] == "https://example.com/pkg-1.0.tar.gz"


def test_run_fetch_returns_error_on_download_failure():
    with patch(
        "nidhogg.fetching.pypi_fetch.fetched_package",
        side_effect=PackageReadError("boom"),
    ):
        exit_code = _run_fetch(
            "somepkg",
            None,
            None,
            as_json=False,
            verbose=False,
            keep_download=None,
            history_dir=None,
        )
    assert exit_code == 2


def test_run_fetch_writes_history(tmp_path: Path):
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    history_dir = tmp_path / "history"

    @contextmanager
    def _fake_fetched_package(
        name,  # noqa: ARG001
        version=None,  # noqa: ARG001
        *,
        keep=False,  # noqa: ARG001
        keep_dir=None,  # noqa: ARG001
    ):
        yield extracted, "1.0", "https://example.com/pkg-1.0.tar.gz"

    with patch("nidhogg.fetching.pypi_fetch.fetched_package", _fake_fetched_package):
        _run_fetch(
            "somepkg",
            None,
            None,
            as_json=False,
            verbose=False,
            keep_download=None,
            history_dir=history_dir,
        )
    assert len(list(history_dir.glob("*.jsonl"))) == 1


def test_analyse_new_package_uses_real_name_not_extract_dir_name(tmp_path: Path):
    """The download always extracts into a dir literally named "extracted"."""
    extracted = tmp_path / "extracted"
    (extracted / "pkg").mkdir(parents=True)
    (extracted / "pkg" / "module.py").write_text("x = 1", encoding="utf-8")

    @contextmanager
    def _fake_fetched_package(name, *, keep=False, keep_dir=None):  # noqa: ARG001
        yield extracted, "1.0", "https://example.com/pkg-1.0.tar.gz"

    with patch("nidhogg.fetching.pypi_fetch.fetched_package", _fake_fetched_package):
        result = _analyse_new_package("real-pkg-name", keep_download=None)

    assert result is not None
    assert result.name == "real-pkg-name"
    assert result.version == "1.0"
    assert result.download_url == "https://example.com/pkg-1.0.tar.gz"


def test_run_monitor_processes_one_batch_then_stops(tmp_path: Path):
    """KeyboardInterrupt after the first iteration exits the loop cleanly."""
    index_file = tmp_path / "state.json"
    fake_client = MagicMock()
    fake_client.current_serial.side_effect = [100, 100]
    fake_client.entries_since.return_value = [
        ChangelogEntry(
            name="newpkg", version="", timestamp=1, action="create", serial=99
        )
    ]

    fake_analysis = PackageAnalysis(name="newpkg", path=tmp_path)

    def _fake_analyse_new_package(name, **kwargs):  # noqa: ARG001
        return fake_analysis

    def _fake_sleep(seconds):  # noqa: ARG001
        raise KeyboardInterrupt

    with (
        patch("nidhogg.fetching.changelog.ChangelogClient", return_value=fake_client),
        patch("nidhogg.cli._analyse_new_package", _fake_analyse_new_package),
        patch("time.sleep", _fake_sleep),
    ):
        exit_code = _run_monitor(
            interval=0,
            index_file=index_file,
            concurrency=2,
            keep_download=None,
            as_json=False,
            history_dir=None,
            verbose=False,
        )

    assert exit_code == 0
    state = load_state(index_file)
    assert state == MonitorState(last_serial=100)


def test_initial_backfill_serial_returns_estimated_start_when_few_packages():
    """Fewer new packages exist in the estimated window than the backfill target."""
    fake_client = MagicMock()
    fake_client.current_serial.return_value = 1000
    fake_client.entries_since.return_value = [
        ChangelogEntry(
            name="pkg1", version="", timestamp=1, action="create", serial=950
        )
    ]

    result = _initial_backfill_serial(fake_client, backfill=40)

    assert result == 0
    fake_client.entries_since.assert_called_once_with(0)


def test_initial_backfill_serial_returns_serial_preceding_last_n_packages():
    """More new packages exist than the backfill target: trim to the last N."""
    fake_client = MagicMock()
    fake_client.current_serial.return_value = 10000
    fake_client.entries_since.return_value = [
        ChangelogEntry(
            name=f"pkg{i}", version="", timestamp=i, action="create", serial=i
        )
        for i in range(1, 51)
    ]

    result = _initial_backfill_serial(fake_client, backfill=40)

    assert result == 10


def test_run_monitor_bootstraps_backfill_when_no_persisted_state(tmp_path: Path):
    """First-ever run (no state file) backfills recent packages instead of starting at "now"."""
    index_file = tmp_path / "state.json"
    fake_client = MagicMock()
    fake_client.current_serial.side_effect = [10000, 10000]
    fake_client.entries_since.return_value = []

    def _fake_sleep(seconds):  # noqa: ARG001
        raise KeyboardInterrupt

    with (
        patch("nidhogg.fetching.changelog.ChangelogClient", return_value=fake_client),
        patch("time.sleep", _fake_sleep),
    ):
        _run_monitor(
            interval=0,
            index_file=index_file,
            concurrency=2,
            keep_download=None,
            as_json=False,
            history_dir=None,
            verbose=False,
        )

    fake_client.entries_since.assert_any_call(6000)


def test_run_monitor_resumes_from_persisted_serial(tmp_path: Path):
    index_file = tmp_path / "state.json"
    save_state(index_file, MonitorState(last_serial=500))

    fake_client = MagicMock()
    fake_client.current_serial.return_value = 500
    fake_client.entries_since.return_value = []

    def _fake_sleep(seconds):  # noqa: ARG001
        raise KeyboardInterrupt

    with (
        patch("nidhogg.fetching.changelog.ChangelogClient", return_value=fake_client),
        patch("time.sleep", _fake_sleep),
    ):
        _run_monitor(
            interval=0,
            index_file=index_file,
            concurrency=2,
            keep_download=None,
            as_json=False,
            history_dir=None,
            verbose=False,
        )

    fake_client.entries_since.assert_called_once_with(500)


def test_run_monitor_once_runs_single_iteration_and_persists_state(tmp_path: Path):
    index_file = tmp_path / "state.json"
    save_state(index_file, MonitorState(last_serial=500))

    fake_client = MagicMock()
    fake_client.current_serial.return_value = 600
    fake_client.entries_since.return_value = []

    with patch("nidhogg.fetching.changelog.ChangelogClient", return_value=fake_client):
        exit_code = _run_monitor(
            interval=0,
            index_file=index_file,
            concurrency=2,
            keep_download=None,
            as_json=False,
            history_dir=None,
            verbose=False,
            once=True,
        )

    assert exit_code == 0
    fake_client.entries_since.assert_called_once_with(500)
    assert load_state(index_file) == MonitorState(last_serial=600)


def test_run_monitor_once_does_not_loop(tmp_path: Path):
    """--once is for scheduled jobs: a single poll then exit, never time.sleep."""
    index_file = tmp_path / "state.json"
    fake_client = MagicMock()
    fake_client.current_serial.return_value = 100
    fake_client.entries_since.return_value = []

    with (
        patch("nidhogg.fetching.changelog.ChangelogClient", return_value=fake_client),
        patch("time.sleep") as fake_sleep,
    ):
        exit_code = _run_monitor(
            interval=5,
            index_file=index_file,
            concurrency=2,
            keep_download=None,
            as_json=False,
            history_dir=None,
            verbose=False,
            once=True,
        )

    assert exit_code == 0
    fake_sleep.assert_not_called()


def test_run_monitor_continues_after_one_package_fails(tmp_path: Path):
    index_file = tmp_path / "state.json"
    fake_client = MagicMock()
    fake_client.current_serial.return_value = 10
    fake_client.entries_since.return_value = [
        ChangelogEntry(
            name="badpkg", version="", timestamp=1, action="create", serial=1
        ),
        ChangelogEntry(
            name="goodpkg", version="", timestamp=2, action="create", serial=2
        ),
    ]

    fake_analysis = PackageAnalysis(name="goodpkg", path=tmp_path)

    def _fake_analyse_new_package(name, **kwargs):  # noqa: ARG001
        if name == "badpkg":
            raise PackageReadError("network error")
        return fake_analysis

    def _fake_sleep(seconds):  # noqa: ARG001
        raise KeyboardInterrupt

    with (
        patch("nidhogg.fetching.changelog.ChangelogClient", return_value=fake_client),
        patch("nidhogg.cli._analyse_new_package", _fake_analyse_new_package),
        patch("time.sleep", _fake_sleep),
    ):
        exit_code = _run_monitor(
            interval=0,
            index_file=index_file,
            concurrency=2,
            keep_download=None,
            as_json=False,
            history_dir=None,
            verbose=False,
        )

    # The monitor itself always exits 0 (stopped via Ctrl+C); the important
    # assertion is that it reached save_state despite badpkg failing.
    assert exit_code == 0
    assert load_state(index_file) == MonitorState(last_serial=10)


def test_run_monitor_uses_rich_path_when_stdout_is_a_tty(tmp_path: Path):
    """When stdout looks like a terminal, monitor still completes and saves state."""
    index_file = tmp_path / "state.json"
    fake_client = MagicMock()
    fake_client.current_serial.side_effect = [100, 100]
    fake_client.entries_since.return_value = [
        ChangelogEntry(
            name="newpkg", version="", timestamp=1, action="create", serial=99
        )
    ]

    fake_analysis = PackageAnalysis(name="newpkg", path=tmp_path)

    def _fake_analyse_new_package(name, **kwargs):  # noqa: ARG001
        return fake_analysis

    def _fake_sleep(seconds):  # noqa: ARG001
        raise KeyboardInterrupt

    with (
        patch("nidhogg.fetching.changelog.ChangelogClient", return_value=fake_client),
        patch("nidhogg.cli._analyse_new_package", _fake_analyse_new_package),
        patch("time.sleep", _fake_sleep),
        patch("sys.stdout.isatty", return_value=True),
    ):
        exit_code = _run_monitor(
            interval=0,
            index_file=index_file,
            concurrency=2,
            keep_download=None,
            as_json=False,
            history_dir=None,
            verbose=False,
        )

    assert exit_code == 0
    assert load_state(index_file) == MonitorState(last_serial=100)


def test_run_analyze_prints_result_block(tmp_path: Path, capsys):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "module.py").write_text(
        'x = "https://transfer.sh/malbeacon"\n', encoding="utf-8"
    )
    exit_code = _run_analyze(pkg_dir, None, as_json=False, verbose=False)
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "package" in out
    assert "pkg" in out
    assert "findings" in out
    assert "https://transfer.sh/malbeacon" in out


def test_run_monitor_plain_path_prints_rendered_header(tmp_path: Path, capsys):
    """Non-TTY monitor path prints the renderer header, not `=== pkg ===`."""
    index_file = tmp_path / "state.json"
    fake_client = MagicMock()
    fake_client.current_serial.return_value = 100
    fake_client.entries_since.return_value = [
        ChangelogEntry(
            name="newpkg", version="", timestamp=1, action="create", serial=99
        )
    ]

    finding = UrlFinding(
        value="https://c2.evil.example.com/beacon",
        filepath=tmp_path / "module.py",
        lineno=1,
        layer=AnalysisLayer.AST,
    )
    file_analysis = FileAnalysis(filepath=tmp_path / "module.py", findings=[finding])
    fake_analysis = PackageAnalysis(name="newpkg", path=tmp_path, files=[file_analysis])

    def _fake_analyse(name, **kwargs):  # noqa: ARG001
        return fake_analysis

    def _fake_sleep(seconds):  # noqa: ARG001
        raise KeyboardInterrupt

    with (
        patch("nidhogg.fetching.changelog.ChangelogClient", return_value=fake_client),
        patch("nidhogg.cli._analyse_new_package", _fake_analyse),
        patch("time.sleep", _fake_sleep),
        patch("sys.stdout.isatty", return_value=False),
    ):
        exit_code = _run_monitor(
            interval=0,
            index_file=index_file,
            concurrency=1,
            keep_download=None,
            as_json=False,
            history_dir=None,
            verbose=False,
        )
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "── newpkg" in out
    assert "=== newpkg ===" not in out


def test_analyze_check_http_invokes_probe(tmp_path, monkeypatch) -> None:
    from unittest.mock import patch

    from nidhogg import cli

    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "mod.py").write_text('URL = "http://example.com"\n', encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv", ["nidhogg", "analyze", str(pkg), "--check-http", "--json"]
    )
    with patch("nidhogg.enrichment.http_probe.check_urls") as mock_check:
        mock_check.side_effect = lambda findings, **_: findings
        with pytest.raises(SystemExit) as exc:
            cli.main()
    assert exc.value.code == 0
    mock_check.assert_called_once()


def test_fetch_check_http_invokes_probe(tmp_path, monkeypatch) -> None:
    from unittest.mock import patch

    from nidhogg import cli

    extracted = tmp_path / "extracted"
    extracted.mkdir()
    (extracted / "mod.py").write_text('URL = "http://example.com"\n', encoding="utf-8")

    @contextmanager
    def _fake_fetched_package(
        name,  # noqa: ARG001
        version=None,  # noqa: ARG001
        *,
        keep=False,  # noqa: ARG001
        keep_dir=None,  # noqa: ARG001
    ):
        yield extracted, "1.0", "https://example.com/pkg-1.0.tar.gz"

    monkeypatch.setattr(
        "sys.argv", ["nidhogg", "fetch", "somepkg", "--check-http", "--json"]
    )
    with (
        patch("nidhogg.fetching.pypi_fetch.fetched_package", _fake_fetched_package),
        patch("nidhogg.enrichment.http_probe.check_urls") as mock_check,
    ):
        mock_check.side_effect = lambda findings, **_: findings
        with pytest.raises(SystemExit) as exc:
            cli.main()
    assert exc.value.code == 0
    mock_check.assert_called_once()


def test_fetch_check_ssl_invokes_cert_check(tmp_path, monkeypatch) -> None:
    from unittest.mock import patch

    from nidhogg import cli

    extracted = tmp_path / "extracted"
    extracted.mkdir()
    (extracted / "mod.py").write_text('URL = "https://example.com"\n', encoding="utf-8")

    @contextmanager
    def _fake_fetched_package(
        name,  # noqa: ARG001
        version=None,  # noqa: ARG001
        *,
        keep=False,  # noqa: ARG001
        keep_dir=None,  # noqa: ARG001
    ):
        yield extracted, "1.0", "https://example.com/pkg-1.0.tar.gz"

    monkeypatch.setattr(
        "sys.argv", ["nidhogg", "fetch", "somepkg", "--check-ssl", "--json"]
    )
    with (
        patch("nidhogg.fetching.pypi_fetch.fetched_package", _fake_fetched_package),
        patch("nidhogg.enrichment.ssl_cert.check_certificates") as mock_check,
    ):
        mock_check.side_effect = lambda findings, **_: findings
        with pytest.raises(SystemExit) as exc:
            cli.main()
    assert exc.value.code == 0
    mock_check.assert_called_once()


def test_monitor_last_check_http_invokes_probe(tmp_path, monkeypatch) -> None:
    from unittest.mock import patch

    from nidhogg import cli

    extracted = tmp_path / "extracted"
    extracted.mkdir()
    (extracted / "mod.py").write_text('URL = "http://example.com"\n', encoding="utf-8")

    @contextmanager
    def _fake_fetched_package(
        name,  # noqa: ARG001
        version=None,  # noqa: ARG001
        *,
        keep=False,  # noqa: ARG001
        keep_dir=None,  # noqa: ARG001
    ):
        yield extracted, "1.0", "https://example.com/pkg-1.0.tar.gz"

    fake_client = MagicMock()
    fake_client.current_serial.return_value = 100
    fake_client.entries_since.return_value = [
        ChangelogEntry(
            name="newpkg", version="", timestamp=1, action="create", serial=99
        )
    ]

    monkeypatch.setattr(
        "sys.argv",
        [
            "nidhogg",
            "monitor",
            "--last",
            "1",
            "--check-http",
            "--json",
            "--index-file",
            str(tmp_path / "state.json"),
        ],
    )
    with (
        patch("nidhogg.fetching.changelog.ChangelogClient", return_value=fake_client),
        patch("nidhogg.fetching.pypi_fetch.fetched_package", _fake_fetched_package),
        patch("nidhogg.enrichment.http_probe.check_urls") as mock_check,
    ):
        mock_check.side_effect = lambda findings, **_: findings
        with pytest.raises(SystemExit) as exc:
            cli.main()
    assert exc.value.code == 0
    mock_check.assert_called_once()
