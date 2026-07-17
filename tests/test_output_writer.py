"""Tests for output/writer.py."""

from __future__ import annotations

import json
from pathlib import Path

from nidhogg.core.models import (
    AnalysisLayer,
    FileAnalysis,
    FileTag,
    PackageAnalysis,
    UrlFinding,
    UrlTag,
)
from nidhogg.output.writer import _serialise_finding, build_document, write_results


def _pkg(
    tmp_path: Path,
    files: list[FileAnalysis] | None = None,
) -> PackageAnalysis:
    return PackageAnalysis(
        name="testpkg",
        path=tmp_path,
        files=files or [],
    )


def _finding(
    tmp_path: Path,
    url: str = "https://c2.evil.example.com/beacon",
    layer: AnalysisLayer = AnalysisLayer.AST,
    lineno: int = 1,
    tags: set[UrlTag] | None = None,
) -> UrlFinding:
    return UrlFinding(
        value=url,
        filepath=tmp_path / "module.py",
        lineno=lineno,
        layer=layer,
        tags=tags or set(),
    )


def _file(
    tmp_path: Path,
    findings: list[UrlFinding] | None = None,
    tags: set[FileTag] | None = None,
) -> FileAnalysis:
    return FileAnalysis(
        filepath=tmp_path / "module.py",
        tags=tags or set(),
        findings=findings or [],
    )


# ---------------------------------------------------------------------------
# File creation
# ---------------------------------------------------------------------------


def test_write_results_creates_file(tmp_path: Path):
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path), out)
    assert out.exists()


def test_write_results_valid_json(tmp_path: Path):
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path), out)
    data = json.loads(out.read_text())
    assert isinstance(data, dict)


# ---------------------------------------------------------------------------
# Package section
# ---------------------------------------------------------------------------


def test_output_contains_package_name(tmp_path: Path):
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path), out)
    data = json.loads(out.read_text())
    assert data["package"]["name"] == "testpkg"


def test_output_contains_package_path(tmp_path: Path):
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path), out)
    data = json.loads(out.read_text())
    assert data["package"]["path"] == str(tmp_path)


def test_output_contains_package_version_when_known(tmp_path: Path):
    out = tmp_path / "results.json"
    pkg = PackageAnalysis(name="testpkg", path=tmp_path, version="1.2.3")
    write_results(pkg, out)
    data = json.loads(out.read_text())
    assert data["package"]["version"] == "1.2.3"


def test_output_package_version_none_when_unknown(tmp_path: Path):
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path), out)
    data = json.loads(out.read_text())
    assert data["package"]["version"] is None


def test_output_contains_package_download_url_when_known(tmp_path: Path):
    out = tmp_path / "results.json"
    pkg = PackageAnalysis(
        name="testpkg",
        path=tmp_path,
        download_url="https://files.pythonhosted.org/packages/pkg-1.2.3.tar.gz",
    )
    write_results(pkg, out)
    data = json.loads(out.read_text())
    assert (
        data["package"]["download_url"]
        == "https://files.pythonhosted.org/packages/pkg-1.2.3.tar.gz"
    )


# ---------------------------------------------------------------------------
# Summary section
# ---------------------------------------------------------------------------


def test_summary_total_findings_zero(tmp_path: Path):
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path), out)
    data = json.loads(out.read_text())
    assert data["summary"]["total_findings"] == 0


def test_summary_total_files_zero(tmp_path: Path):
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path), out)
    data = json.loads(out.read_text())
    assert data["summary"]["total_files"] == 0


def test_summary_total_findings_count(tmp_path: Path):
    findings = [_finding(tmp_path), _finding(tmp_path, url="https://other.evil.com")]
    files = [_file(tmp_path, findings=findings)]
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path, files=files), out)
    data = json.loads(out.read_text())
    assert data["summary"]["total_findings"] == 2


def test_summary_total_files_count(tmp_path: Path):
    files = [_file(tmp_path), _file(tmp_path)]
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path, files=files), out)
    data = json.loads(out.read_text())
    assert data["summary"]["total_files"] == 2


# ---------------------------------------------------------------------------
# Files section
# ---------------------------------------------------------------------------


def test_files_empty_list_when_no_files(tmp_path: Path):
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path), out)
    data = json.loads(out.read_text())
    assert data["files"] == []


def test_files_findings_empty_list_when_no_findings(tmp_path: Path):
    files = [_file(tmp_path)]
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path, files=files), out)
    data = json.loads(out.read_text())
    assert data["files"][0]["findings"] == []


def test_findings_url_present(tmp_path: Path):
    f = _finding(tmp_path, url="https://c2.evil.example.com/beacon")
    files = [_file(tmp_path, findings=[f])]
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path, files=files), out)
    data = json.loads(out.read_text())
    assert (
        data["files"][0]["findings"][0]["url"] == "https://c2.evil.example.com/beacon"
    )


def test_file_path_is_relative(tmp_path: Path):
    f = _finding(tmp_path)
    files = [_file(tmp_path, findings=[f])]
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path, files=files), out)
    data = json.loads(out.read_text())
    assert data["files"][0]["file"] == "module.py"


def test_findings_lineno_present(tmp_path: Path):
    f = _finding(tmp_path, lineno=42)
    files = [_file(tmp_path, findings=[f])]
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path, files=files), out)
    data = json.loads(out.read_text())
    assert data["files"][0]["findings"][0]["line"] == 42


def test_findings_layer_is_string(tmp_path: Path):
    f = _finding(tmp_path, layer=AnalysisLayer.REGEX)
    files = [_file(tmp_path, findings=[f])]
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path, files=files), out)
    data = json.loads(out.read_text())
    assert data["files"][0]["findings"][0]["layer"] == "regex"


def test_findings_tags_are_sorted_strings(tmp_path: Path):
    f = _finding(tmp_path, tags={UrlTag.VIA_BASE64, UrlTag.RAW_IP})
    files = [_file(tmp_path, findings=[f])]
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path, files=files), out)
    data = json.loads(out.read_text())
    assert data["files"][0]["findings"][0]["tags"] == sorted(
        [UrlTag.VIA_BASE64.value, UrlTag.RAW_IP.value]
    )


def test_file_tags_are_sorted_strings(tmp_path: Path):
    files = [_file(tmp_path, tags={FileTag.TEST, FileTag.DOTFILE})]
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path, files=files), out)
    data = json.loads(out.read_text())
    assert data["files"][0]["tags"] == sorted(
        [FileTag.TEST.value, FileTag.DOTFILE.value]
    )


# ---------------------------------------------------------------------------
# build_document focused test
# ---------------------------------------------------------------------------


def test_build_document_has_files_with_tags() -> None:
    fp = Path("/pkg/README.md")
    finding = UrlFinding(
        "http://evil.test/x", fp, 2, AnalysisLayer.REGEX, {UrlTag.SHORTENER}
    )
    analysis = PackageAnalysis(
        "pkg",
        Path("/pkg"),
        [FileAnalysis(fp, {FileTag.README}, [finding])],
    )
    doc = build_document(analysis)
    assert doc["summary"] == {"total_findings": 1, "total_files": 1}
    file_entry = doc["files"][0]
    assert file_entry["file"] == "README.md"
    assert file_entry["tags"] == ["readme"]
    assert file_entry["findings"][0]["tags"] == ["shortener"]
    assert file_entry["findings"][0]["cert_issuer"] is None
    assert "method" not in file_entry["findings"][0]
    assert "domain_threat" not in file_entry["findings"][0]


def test_serialise_finding_includes_http_fields() -> None:
    finding = UrlFinding(
        value="http://example.com",
        filepath=Path("pkg/x.py"),
        lineno=3,
        layer=AnalysisLayer.REGEX,
        http_status=200,
        http_title="Home",
    )
    doc = _serialise_finding(finding)
    assert doc["http_status"] == 200
    assert doc["http_title"] == "Home"
