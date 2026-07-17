"""Tests for enrichment/http_probe.py."""

from __future__ import annotations

from nidhogg.enrichment.http_probe import _extract_title


def test_extract_title_basic() -> None:
    assert _extract_title("<html><head><title>Hello</title></head></html>") == "Hello"


def test_extract_title_collapses_whitespace() -> None:
    assert _extract_title("<title>  Hello\n   world  </title>") == "Hello world"


def test_extract_title_truncates_to_200_chars() -> None:
    long = "x" * 500
    result = _extract_title(f"<title>{long}</title>")
    assert result is not None
    assert len(result) == 200


def test_extract_title_missing_returns_none() -> None:
    assert _extract_title("<html><body>no title here</body></html>") is None


def test_extract_title_empty_returns_none() -> None:
    assert _extract_title("<title>   </title>") is None


def test_extract_title_strips_control_characters() -> None:
    result = _extract_title("<title>Home\x1b[2J\x07\x1b]0;evil\x07 Page</title>")
    assert result is not None
    assert "\x1b" not in result
    assert "\x07" not in result
    assert result == "Home Page"


def test_extract_title_strips_private_mode_csi_cleanly() -> None:
    result = _extract_title("<title>Before\x1b[?25lAfter\x1b[?1049h!</title>")
    assert result == "BeforeAfter!"


from unittest.mock import MagicMock, patch  # noqa: E402

from nidhogg.enrichment import http_probe  # noqa: E402


def _fake_response(body: bytes) -> MagicMock:
    resp = MagicMock()
    resp.status = 200
    resp.read.return_value = body
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    return resp


def test_probe_200_with_title() -> None:
    resp = _fake_response(b"<title>Live Site</title>")
    with patch.object(http_probe.urllib.request, "urlopen", return_value=resp):
        result = http_probe._probe("http://example.com", timeout=5.0)  # noqa: SLF001
    assert result == (200, "Live Site")


def test_probe_non_html_body_no_title() -> None:
    resp = _fake_response(b"\x89PNG\r\n binary junk")
    with patch.object(http_probe.urllib.request, "urlopen", return_value=resp):
        result = http_probe._probe("http://example.com/img.png", timeout=5.0)  # noqa: SLF001
    assert result == (200, None)


def test_probe_http_error_returns_status() -> None:
    err = http_probe.urllib.error.HTTPError(
        url="http://example.com/missing",
        code=404,
        msg="Not Found",
        hdrs=None,  # type: ignore[arg-type]
        fp=None,
    )
    with patch.object(http_probe.urllib.request, "urlopen", side_effect=err):
        result = http_probe._probe("http://example.com/missing", timeout=5.0)  # noqa: SLF001
    assert result == (404, None)


def test_probe_timeout_returns_none() -> None:
    with patch.object(http_probe.urllib.request, "urlopen", side_effect=TimeoutError()):
        result = http_probe._probe("http://example.com", timeout=5.0)  # noqa: SLF001
    assert result is None


from pathlib import Path  # noqa: E402

from nidhogg.core.models import AnalysisLayer, FileAnalysis, UrlFinding  # noqa: E402
from nidhogg.enrichment.http_probe import check_urls, prune_unresponsive  # noqa: E402


def _finding(url: str) -> UrlFinding:
    return UrlFinding(
        value=url,
        filepath=Path("pkg/evil.py"),
        lineno=1,
        layer=AnalysisLayer.REGEX,
    )


def test_check_urls_sets_status_and_title() -> None:
    finding = _finding("http://example.com")
    with patch.object(http_probe, "_probe", return_value=(200, "Home")):
        result = check_urls([finding])
    assert result[0].http_status == 200
    assert result[0].http_title == "Home"


def test_check_urls_ignores_non_http_schemes() -> None:
    finding = _finding("ftp://files.example.com/x")
    with patch.object(http_probe, "_probe") as mock_probe:
        check_urls([finding])
    mock_probe.assert_not_called()
    assert finding.http_status is None


def test_check_urls_duplicate_urls_share_one_probe() -> None:
    a = _finding("http://example.com")
    b = _finding("http://example.com")
    with patch.object(http_probe, "_probe", return_value=(200, "Home")) as mock_probe:
        check_urls([a, b])
    assert mock_probe.call_count == 1
    assert a.http_status == 200
    assert b.http_status == 200


def test_check_urls_probe_failure_leaves_none() -> None:
    finding = _finding("http://example.com")
    with patch.object(http_probe, "_probe", return_value=None):
        check_urls([finding])
    assert finding.http_status is None
    assert finding.http_title is None


def test_check_urls_two_distinct_urls_get_independent_results() -> None:
    a = _finding("http://example.com")
    b = _finding("http://other.example.com")

    def fake_probe(url: str, *, timeout: float) -> tuple[int, str] | None:  # noqa: ARG001
        return (200, "Home") if url == "http://example.com" else (404, "Other")

    with patch.object(http_probe, "_probe", side_effect=fake_probe):
        check_urls([a, b])

    assert a.http_status == 200
    assert a.http_title == "Home"
    assert b.http_status == 404
    assert b.http_title == "Other"


def test_prune_unresponsive_drops_http_finding_with_no_status() -> None:
    finding = _finding("http://example.com")
    fa = FileAnalysis(filepath=Path("pkg/evil.py"), findings=[finding])
    prune_unresponsive([fa])
    assert fa.findings == []


def test_prune_unresponsive_keeps_http_finding_with_status() -> None:
    finding = _finding("http://example.com")
    finding.http_status = 200
    fa = FileAnalysis(filepath=Path("pkg/evil.py"), findings=[finding])
    prune_unresponsive([fa])
    assert fa.findings == [finding]


def test_prune_unresponsive_keeps_non_http_finding_without_status() -> None:
    finding = _finding("ftp://files.example.com/x")
    fa = FileAnalysis(filepath=Path("pkg/evil.py"), findings=[finding])
    prune_unresponsive([fa])
    assert fa.findings == [finding]
