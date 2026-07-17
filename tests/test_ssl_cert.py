"""Tests for enrichment/ssl_cert.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from nidhogg.core.models import AnalysisLayer, UrlFinding
from nidhogg.enrichment.ssl_cert import check_certificates


def _finding(url: str) -> UrlFinding:
    return UrlFinding(
        value=url,
        filepath=Path("pkg/evil.py"),
        lineno=1,
        layer=AnalysisLayer.REGEX,
    )


def test_check_certificates_letsencrypt_sets_issuer() -> None:
    finding = _finding("https://evil.example.com/payload")
    with patch(
        "nidhogg.enrichment.ssl_cert._get_cert_issuer",
        return_value="Let's Encrypt",
    ):
        result = check_certificates([finding])
    assert result[0].cert_issuer == "Let's Encrypt"


def test_check_certificates_other_ca_sets_issuer() -> None:
    finding = _finding("https://legit.example.com/resource")
    with patch(
        "nidhogg.enrichment.ssl_cert._get_cert_issuer", return_value="DigiCert Inc"
    ):
        result = check_certificates([finding])
    assert result[0].cert_issuer == "DigiCert Inc"


def test_check_certificates_connection_failure_no_issuer() -> None:
    finding = _finding("https://unreachable.example/path")
    with patch("nidhogg.enrichment.ssl_cert._get_cert_issuer", return_value=None):
        result = check_certificates([finding])
    assert result[0].cert_issuer is None


def test_check_certificates_http_url_skipped() -> None:
    finding = _finding("http://evil.example.com/payload")
    with patch("nidhogg.enrichment.ssl_cert._get_cert_issuer") as mock_get:
        result = check_certificates([finding])
    mock_get.assert_not_called()
    assert result[0].cert_issuer is None


def test_check_certificates_ftp_url_skipped() -> None:
    finding = _finding("ftp://files.example.com/data")
    with patch("nidhogg.enrichment.ssl_cert._get_cert_issuer") as mock_get:
        check_certificates([finding])
    mock_get.assert_not_called()


def test_check_certificates_deduplicates_hostname_calls() -> None:
    f1 = _finding("https://evil.example.com/a")
    f2 = _finding("https://evil.example.com/b")
    call_count = 0

    def _once(hostname: str, *, timeout: float) -> str:  # noqa: ARG001
        nonlocal call_count
        call_count += 1
        return "Let's Encrypt"

    with patch("nidhogg.enrichment.ssl_cert._get_cert_issuer", side_effect=_once):
        result = check_certificates([f1, f2])

    assert call_count == 1
    assert all(f.cert_issuer == "Let's Encrypt" for f in result)


def test_check_certificates_empty_findings_returns_empty() -> None:
    result = check_certificates([])
    assert result == []


def test_check_certificates_no_https_findings_skips_all() -> None:
    findings = [_finding("http://a.com"), _finding("ftp://b.com")]
    with patch("nidhogg.enrichment.ssl_cert._get_cert_issuer") as mock_get:
        result = check_certificates(findings)
    mock_get.assert_not_called()
    assert all(f.cert_issuer is None for f in result)


def test_check_certificates_mutation_visible_via_fileanalysis(monkeypatch) -> None:
    """Verify in-place mutation of findings visible through PackageAnalysis.findings."""
    from nidhogg.core.models import FileAnalysis, PackageAnalysis
    from nidhogg.enrichment import ssl_cert

    monkeypatch.setattr(
        ssl_cert,
        "_get_cert_issuer",
        lambda _, *, timeout: "Let's Encrypt",  # noqa: ARG005
    )
    f = UrlFinding("https://x.test/a", Path("a.py"), 1, AnalysisLayer.REGEX)
    pkg = PackageAnalysis("p", Path("/p"), [FileAnalysis(Path("a.py"), set(), [f])])
    ssl_cert.check_certificates(pkg.findings)
    assert pkg.files[0].findings[0].cert_issuer == "Let's Encrypt"
