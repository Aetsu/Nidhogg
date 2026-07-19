"""Tests for analysis/walker.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from nidhogg.analysis.walker import analyze_package
from nidhogg.core.exceptions import PackageReadError
from nidhogg.core.models import (
    AnalysisLayer,
    FileTag,
    PackageAnalysis,
    UrlFinding,
)

PATCH_L1 = "nidhogg.analysis.walker.extract_urls_regex"
PATCH_L2 = "nidhogg.analysis.walker.extract_urls_ast"


def _make_finding(filepath: Path) -> UrlFinding:
    return UrlFinding(
        value="https://evil.example.com",
        filepath=filepath,
        lineno=1,
        layer=AnalysisLayer.REGEX,
    )


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


def test_analyze_package_finds_py_files(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1")
    (tmp_path / "b.py").write_text("y = 2")

    with (
        patch(PATCH_L1, return_value=[]),
        patch(PATCH_L2, return_value=([], False)),
    ):
        result = analyze_package(tmp_path)

    assert isinstance(result, PackageAnalysis)
    assert result.name == tmp_path.name
    assert result.path == tmp_path


def test_analyze_package_name_override_replaces_dir_name(tmp_path: Path):
    """Fetch/monitor extract into a fixed-name temp dir; name must override it."""
    (tmp_path / "a.py").write_text("x = 1")

    with (
        patch(PATCH_L1, return_value=[]),
        patch(PATCH_L2, return_value=([], False)),
    ):
        result = analyze_package(tmp_path, name="real-package-name")

    assert result.name == "real-package-name"


def test_analyze_package_version_defaults_none(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1")

    with (
        patch(PATCH_L1, return_value=[]),
        patch(PATCH_L2, return_value=([], False)),
    ):
        result = analyze_package(tmp_path)

    assert result.version is None


def test_analyze_package_version_override_recorded(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1")

    with (
        patch(PATCH_L1, return_value=[]),
        patch(PATCH_L2, return_value=([], False)),
    ):
        result = analyze_package(tmp_path, version="1.2.3")

    assert result.version == "1.2.3"


def test_analyze_package_download_url_override_recorded(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1")

    with (
        patch(PATCH_L1, return_value=[]),
        patch(PATCH_L2, return_value=([], False)),
    ):
        result = analyze_package(
            tmp_path, download_url="https://files.pythonhosted.org/pkg-1.2.3.tar.gz"
        )

    assert result.download_url == "https://files.pythonhosted.org/pkg-1.2.3.tar.gz"


def test_analyze_package_finds_files_recursively(tmp_path: Path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (tmp_path / "top.py").write_text("")
    (sub / "nested.py").write_text("")

    with (
        patch(PATCH_L1, return_value=[]) as mock_l1,
        patch(PATCH_L2, return_value=([], False)),
    ):
        analyze_package(tmp_path)

    called_paths = {call.args[1] for call in mock_l1.call_args_list}
    assert tmp_path / "top.py" in called_paths
    assert sub / "nested.py" in called_paths


def test_analyze_package_excludes_pycache(tmp_path: Path):
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "cached.py").write_text("secret = 'https://evil.com'")
    (tmp_path / "real.py").write_text("")

    with (
        patch(PATCH_L1, return_value=[]) as mock_l1,
        patch(PATCH_L2, return_value=([], False)),
    ):
        analyze_package(tmp_path)

    called_paths = {call.args[1] for call in mock_l1.call_args_list}
    assert not any("__pycache__" in str(p) for p in called_paths)


def test_analyze_package_no_analysable_files_returns_empty(tmp_path: Path):
    (tmp_path / "data.bin").write_bytes(b"\x00\x01")

    with (
        patch(PATCH_L1, return_value=[]),
        patch(PATCH_L2, return_value=([], False)),
    ):
        result = analyze_package(tmp_path)

    assert result.files == []
    assert result.findings == []


# ---------------------------------------------------------------------------
# Text-file whitelist
# ---------------------------------------------------------------------------


def test_analyze_package_includes_whitelisted_text_files(tmp_path: Path):
    (tmp_path / "code.py").write_text("")
    (tmp_path / "notes.rst").write_text("")
    (tmp_path / "notes.txt").write_text("")
    (tmp_path / "setup.cfg").write_text("")
    (tmp_path / "pyproject.toml").write_text("")
    (tmp_path / "image.png").write_bytes(b"\x00")

    with (
        patch(PATCH_L1, return_value=[]) as mock_l1,
        patch(PATCH_L2, return_value=([], False)),
    ):
        result = analyze_package(tmp_path)

    analysed_names = {fa.filepath.name for fa in result.files}
    assert analysed_names == {
        "code.py",
        "notes.rst",
        "notes.txt",
        "setup.cfg",
        "pyproject.toml",
    }
    # Layer1 (regex) runs on every whitelisted file, not just .py.
    assert mock_l1.call_count == len(analysed_names)


def test_analyze_package_runs_ast_only_on_py_files(tmp_path: Path):
    (tmp_path / "code.py").write_text("")
    (tmp_path / "notes.txt").write_text("")

    with (
        patch(PATCH_L1, return_value=[]),
        patch(PATCH_L2, return_value=([], False)) as mock_l2,
    ):
        analyze_package(tmp_path)

    assert mock_l2.call_count == 1


@pytest.mark.parametrize(
    "readme_name",
    ["README.md", "README.rst", "README.txt", "README", "readme.md"],
)
def test_analyze_package_excludes_readme_files(tmp_path: Path, readme_name: str):
    (tmp_path / "code.py").write_text("")
    (tmp_path / readme_name).write_text("See https://readme-example.test/docs")

    with (
        patch(PATCH_L1, return_value=[]),
        patch(PATCH_L2, return_value=([], False)),
    ):
        result = analyze_package(tmp_path)

    analysed_names = {fa.filepath.name for fa in result.files}
    assert readme_name not in analysed_names


# ---------------------------------------------------------------------------
# Findings aggregation
# ---------------------------------------------------------------------------


def test_analyze_package_collects_findings_from_both_layers(tmp_path: Path):
    py_file = tmp_path / "evil.py"
    py_file.write_text("url = 'https://evil.example.com'")

    finding1 = _make_finding(py_file)
    finding2 = UrlFinding(
        value="https://other.example.com",
        filepath=py_file,
        lineno=1,
        layer=AnalysisLayer.AST,
    )

    with (
        patch(PATCH_L1, return_value=[finding1]),
        patch(PATCH_L2, return_value=([finding2], False)),
    ):
        result = analyze_package(tmp_path)

    assert len(result.findings) == 2


# ---------------------------------------------------------------------------
# File tags
# ---------------------------------------------------------------------------


def test_walker_excludes_readme_from_fixture_package() -> None:
    root = Path(__file__).parent / "fixtures" / "pkg_basic"
    analysis = analyze_package(root)
    assert all(fa.filepath.name.lower() != "readme.md" for fa in analysis.files)


def test_walker_flags_dynamic_exec_file(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg_dynamic"
    pkg.mkdir()
    # Written as fixture source for static AST analysis only — never executed.
    (pkg / "evil.py").write_text('eval("1+1")\n')

    analysis = analyze_package(pkg)

    evil = next(fa for fa in analysis.files if fa.filepath.name == "evil.py")
    assert FileTag.DYNAMIC_EXEC in evil.tags


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def test_analyze_package_skips_unreadable_file(tmp_path: Path):
    readable = tmp_path / "good.py"
    readable.write_text("x = 1")
    unreadable = tmp_path / "bad.py"
    unreadable.write_text("")
    unreadable.chmod(0o000)

    try:
        with (
            patch(PATCH_L1, return_value=[]),
            patch(PATCH_L2, return_value=([], False)),
        ):
            result = analyze_package(tmp_path)
        assert isinstance(result, PackageAnalysis)
    finally:
        unreadable.chmod(0o644)


def test_analyze_package_raises_on_missing_path(tmp_path: Path):
    with pytest.raises(PackageReadError, match="not found"):
        analyze_package(tmp_path / "nonexistent")


def test_analyze_package_raises_on_file_not_dir(tmp_path: Path):
    f = tmp_path / "file.py"
    f.write_text("")

    with pytest.raises(PackageReadError, match="not a directory"):
        analyze_package(f)


# ---------------------------------------------------------------------------
# Binary scanning
# ---------------------------------------------------------------------------


def test_analyze_package_scans_binaries_when_check_binaries_true(
    tmp_path: Path,
) -> None:
    (tmp_path / "helper.dll").write_bytes(b"not a real pe")

    with (
        patch(PATCH_L1, return_value=[]),
        patch(PATCH_L2, return_value=([], False)),
    ):
        result = analyze_package(tmp_path, check_binaries=True)

    assert len(result.binaries) == 1
    assert result.binaries[0].name == "helper.dll"


def test_analyze_package_skips_binaries_by_default(tmp_path: Path) -> None:
    (tmp_path / "helper.dll").write_bytes(b"not a real pe")

    with (
        patch(PATCH_L1, return_value=[]),
        patch(PATCH_L2, return_value=([], False)),
    ):
        result = analyze_package(tmp_path)

    assert result.binaries == []


def test_analyze_package_no_binaries_is_empty_list(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1")

    with (
        patch(PATCH_L1, return_value=[]),
        patch(PATCH_L2, return_value=([], False)),
    ):
        result = analyze_package(tmp_path, check_binaries=True)

    assert result.binaries == []
