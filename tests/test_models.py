"""Tests for the shared data models."""

from __future__ import annotations

from pathlib import Path

from nidhogg.core.models import (
    AnalysisLayer,
    BinaryFinding,
    BinaryFormat,
    FileAnalysis,
    FileTag,
    PackageAnalysis,
    UrlFinding,
    UrlTag,
)


def test_urlfinding_defaults_empty_tags_and_no_cert() -> None:
    finding = UrlFinding(
        value="http://x.test",
        filepath=Path("a.py"),
        lineno=1,
        layer=AnalysisLayer.AST,
    )
    assert finding.tags == set()
    assert finding.cert_issuer is None


def test_fileanalysis_defaults_empty_tags_and_findings() -> None:
    fa = FileAnalysis(filepath=Path("a.py"))
    assert fa.tags == set()
    assert fa.findings == []


def test_packageanalysis_findings_property_flattens_all_files() -> None:
    f1 = UrlFinding("http://a.test", Path("a.py"), 1, AnalysisLayer.REGEX)
    f2 = UrlFinding("http://b.test", Path("b.py"), 2, AnalysisLayer.AST)
    pkg = PackageAnalysis(
        name="p",
        path=Path("/p"),
        files=[
            FileAnalysis(Path("a.py"), {FileTag.README}, [f1]),
            FileAnalysis(Path("b.py"), set(), [f2]),
        ],
    )
    assert pkg.findings == [f1, f2]


def test_urlfinding_http_fields_default_none() -> None:
    finding = UrlFinding(
        value="http://example.com",
        filepath=Path("pkg/x.py"),
        lineno=1,
        layer=AnalysisLayer.REGEX,
    )
    assert finding.http_status is None
    assert finding.http_title is None


def test_urltag_and_filetag_values_are_stable() -> None:
    assert UrlTag.VIA_BASE64.value == "via_base64"
    assert UrlTag.RAW_IP.value == "raw_ip"
    assert FileTag.README.value == "readme"
    assert FileTag.DYNAMIC_EXEC.value == "dynamic_exec"


def test_binaryfinding_holds_all_fields() -> None:
    finding = BinaryFinding(
        name="helper.dll",
        filepath=Path("pkg/native/helper.dll"),
        sha256="a" * 64,
        format=BinaryFormat.PE,
        signed=True,
        signer="CN=Example Corp",
    )
    assert finding.name == "helper.dll"
    assert finding.format is BinaryFormat.PE
    assert finding.signed is True
    assert finding.signer == "CN=Example Corp"


def test_binaryformat_values_are_stable() -> None:
    assert BinaryFormat.PE.value == "pe"
    assert BinaryFormat.MACHO.value == "macho"
    assert BinaryFormat.ELF.value == "elf"
    assert BinaryFormat.UNKNOWN.value == "unknown"


def test_packageanalysis_binaries_defaults_empty_list() -> None:
    pkg = PackageAnalysis(name="p", path=Path("/p"))
    assert pkg.binaries == []
