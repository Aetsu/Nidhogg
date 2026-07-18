"""Tests for analysis/layer1_regex.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from nidhogg.analysis.layer1_regex import (
    _is_private_ipv4,
    _is_private_ipv6,
    extract_urls_regex,
)
from nidhogg.core.models import AnalysisLayer, UrlFinding, UrlTag

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _urls(source: str, tmp_path: Path) -> list[str]:
    return [f.value for f in extract_urls_regex(source, tmp_path / "f.py")]


# ---------------------------------------------------------------------------
# Basic detection
# ---------------------------------------------------------------------------


def test_url_literal_in_assignment(tmp_path: Path):
    source = "url = 'https://evil.example.com/payload'"
    findings = extract_urls_regex(source, tmp_path / "f.py")
    assert len(findings) == 1
    assert findings[0].value == "https://evil.example.com/payload"


def test_url_in_comment(tmp_path: Path):
    source = "x = 1  # see https://docs.python.org/3/"
    findings = extract_urls_regex(source, tmp_path / "f.py")
    assert len(findings) == 1
    assert findings[0].value == "https://docs.python.org/3/"


def test_multiple_urls_in_file(tmp_path: Path):
    source = "a = 'https://evil.com/a'\nb = 'http://bad.com/b'"
    assert _urls(source, tmp_path) == ["https://evil.com/a", "http://bad.com/b"]


def test_no_urls_returns_empty(tmp_path: Path):
    source = "x = 42\ny = 'hello world'"
    assert extract_urls_regex(source, tmp_path / "f.py") == []


# ---------------------------------------------------------------------------
# Scheme coverage
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://example.com",
        "ftp://files.example.com/file.tar.gz",
        "ws://stream.example.com/feed",
        "wss://stream.example.com/feed",
    ],
)
def test_all_supported_schemes(url: str, tmp_path: Path):
    assert _urls(f"u = '{url}'", tmp_path) == [url]


def test_unsupported_scheme_not_matched(tmp_path: Path):
    assert _urls("x = 'ssh://host.example.com'", tmp_path) == []


# ---------------------------------------------------------------------------
# Line numbers
# ---------------------------------------------------------------------------


def test_lineno_first_line(tmp_path: Path):
    source = "url = 'https://evil.com'"
    findings = extract_urls_regex(source, tmp_path / "f.py")
    assert findings[0].lineno == 1


def test_lineno_third_line(tmp_path: Path):
    source = "x = 1\ny = 2\nurl = 'https://evil.com'"
    findings = extract_urls_regex(source, tmp_path / "f.py")
    assert findings[0].lineno == 3


def test_multiple_urls_correct_linenos(tmp_path: Path):
    source = "a = 'https://a.com'\n\nb = 'https://b.com'"
    findings = extract_urls_regex(source, tmp_path / "f.py")
    assert findings[0].lineno == 1
    assert findings[1].lineno == 3


# ---------------------------------------------------------------------------
# Trailing punctuation stripping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://evil.com/path.", "https://evil.com/path"),
        ("https://evil.com/path,", "https://evil.com/path"),
        ("https://evil.com/path)", "https://evil.com/path"),
        ("https://evil.com/path'", "https://evil.com/path"),
        ('https://evil.com/path"', "https://evil.com/path"),
    ],
)
def test_trailing_punctuation_stripped(raw: str, expected: str, tmp_path: Path):
    assert _urls(raw, tmp_path) == [expected]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # JSON-style wrapping: `}` blocked the trailing quote from stripping.
        ('{"url": "https://evil.com/path"}', "https://evil.com/path"),
        # f-string placeholder glued right after the URL.
        ("https://api.telegram.org/bot{token}", "https://api.telegram.org/bot"),
        # raw HTML glued with no whitespace: `<a href="URL"><img ...>`.
        ('https://youtu.be/Kwgaz00gUXw"><img', "https://youtu.be/Kwgaz00gUXw"),
        # Python code snippet glued after the URL: `parse('URL').entries[:5]`.
        ("https://hnrss.org/frontpage').entries[:5]", "https://hnrss.org/frontpage"),
    ],
)
def test_weird_characters_truncate_url(raw: str, expected: str, tmp_path: Path):
    assert _urls(raw, tmp_path) == [expected]


def test_url_with_query_string_preserved(tmp_path: Path):
    url = "https://evil.com/path?foo=bar&baz=1"
    assert _urls(f"u = '{url}'", tmp_path) == [url]


def test_url_with_path_preserved(tmp_path: Path):
    url = "https://evil.com/a/b/c"
    assert _urls(f"u = '{url}'", tmp_path) == [url]


# ---------------------------------------------------------------------------
# Finding metadata
# ---------------------------------------------------------------------------


def test_finding_layer_is_regex(tmp_path: Path):
    findings = extract_urls_regex("u = 'https://x.com'", tmp_path / "f.py")
    assert findings[0].layer is AnalysisLayer.REGEX


def test_literal_url_has_no_tags(tmp_path: Path) -> None:
    findings = extract_urls_regex('x = "http://evil.test/a"\n', tmp_path / "f.py")
    assert findings[0].tags == set()


def test_finding_filepath_stored(tmp_path: Path):
    fp = tmp_path / "evil.py"
    findings = extract_urls_regex("u = 'https://x.com'", fp)
    assert findings[0].filepath == fp


# ---------------------------------------------------------------------------
# IP detection — network-call context
# ---------------------------------------------------------------------------


def _ip_findings(source: str, tmp_path: Path) -> list[UrlFinding]:
    return [
        f
        for f in extract_urls_regex(source, tmp_path / "f.py")
        if UrlTag.RAW_IP in f.tags
    ]


@pytest.mark.parametrize(
    "source",
    [
        's.connect(("185.220.101.1", 4444))',
        "socket.connect(('185.220.101.1', 80))",
    ],
)
def test_ipv4_in_connect_call_detected(source: str, tmp_path: Path):
    findings = _ip_findings(source, tmp_path)
    assert len(findings) == 1
    assert findings[0].value == "185.220.101.1"


def test_ipv4_in_urlopen_call_detected(tmp_path: Path):
    source = 'urlopen("185.220.101.1:8080/payload")'
    findings = _ip_findings(source, tmp_path)
    assert len(findings) == 1
    assert findings[0].value == "185.220.101.1"


def test_ipv4_in_requests_get_detected(tmp_path: Path):
    source = 'requests.get("185.220.101.1/data")'
    findings = _ip_findings(source, tmp_path)
    assert len(findings) == 1
    assert findings[0].value == "185.220.101.1"


def test_ipv4_in_create_connection_detected(tmp_path: Path):
    source = 'create_connection(("185.220.101.1", 443))'
    findings = _ip_findings(source, tmp_path)
    assert len(findings) == 1
    assert findings[0].value == "185.220.101.1"


def test_ipv4_in_https_connection_detected(tmp_path: Path):
    source = 'conn = HTTPSConnection("185.220.101.1")'
    findings = _ip_findings(source, tmp_path)
    assert len(findings) == 1
    assert findings[0].value == "185.220.101.1"


# ---------------------------------------------------------------------------
# IP detection — private/loopback filtering
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",
        "10.255.255.255",
    ],
)
def test_private_ipv4_rfc1918_10_filtered(ip: str, tmp_path: Path):
    assert _ip_findings(f's.connect(("{ip}", 80))', tmp_path) == []


@pytest.mark.parametrize(
    "ip",
    [
        "192.168.1.1",
        "192.168.0.254",
    ],
)
def test_private_ipv4_rfc1918_192_168_filtered(ip: str, tmp_path: Path):
    assert _ip_findings(f's.connect(("{ip}", 80))', tmp_path) == []


@pytest.mark.parametrize(
    "ip",
    [
        "172.16.0.1",
        "172.31.255.254",
    ],
)
def test_private_ipv4_rfc1918_172_16_filtered(ip: str, tmp_path: Path):
    assert _ip_findings(f's.connect(("{ip}", 80))', tmp_path) == []


def test_loopback_ipv4_filtered(tmp_path: Path):
    assert _ip_findings('s.connect(("127.0.0.1", 80))', tmp_path) == []


def test_ipv4_without_network_context_not_detected(tmp_path: Path):
    # IP appears in a plain assignment — no connection call on the same line.
    source = 'c2_host = "185.220.101.1"'
    assert _ip_findings(source, tmp_path) == []


# ---------------------------------------------------------------------------
# IP detection — IPv6
# ---------------------------------------------------------------------------


def test_ipv6_full_in_connect_detected(tmp_path: Path):
    source = 's.connect(("2606:4700:4700:0000:0000:0000:0000:1111", 80))'
    findings = _ip_findings(source, tmp_path)
    assert len(findings) == 1
    assert "2606" in findings[0].value


def test_ipv6_compressed_in_connect_detected(tmp_path: Path):
    source = 's.connect(("2001:db8::c2ef", 4444))'
    findings = _ip_findings(source, tmp_path)
    assert len(findings) == 1
    assert findings[0].value == "2001:db8::c2ef"


def test_ipv6_loopback_filtered(tmp_path: Path):
    assert _ip_findings('s.connect(("::1", 80))', tmp_path) == []


def test_ipv6_link_local_filtered(tmp_path: Path):
    assert _ip_findings('s.connect(("fe80::1", 80))', tmp_path) == []


# ---------------------------------------------------------------------------
# IP detection — no double-reporting when IP is inside a URL
# ---------------------------------------------------------------------------


def test_ipv4_inside_http_url_not_reported_as_ip(tmp_path: Path):
    # The URL regex already catches http://185.220.101.1/path;
    # the IP regex must not emit a second finding for the bare IP.
    source = 'requests.get("http://185.220.101.1/payload")'
    findings = extract_urls_regex(source, tmp_path / "f.py")
    ip_findings = [f for f in findings if UrlTag.RAW_IP in f.tags]
    url_findings = [f for f in findings if f.tags == set()]
    assert len(ip_findings) == 0
    assert len(url_findings) == 1
    assert "185.220.101.1" in url_findings[0].value


# ---------------------------------------------------------------------------
# IP detection — finding metadata
# ---------------------------------------------------------------------------


def test_ip_in_network_context_tagged_raw_ip() -> None:
    src = "requests.get('x')\nsock.connect(('8.8.8.8', 80))\n"
    findings = extract_urls_regex(src, Path("a.py"))
    ip_findings = [f for f in findings if f.value == "8.8.8.8"]
    assert ip_findings
    assert UrlTag.RAW_IP in ip_findings[0].tags


def test_ip_finding_layer_is_regex(tmp_path: Path):
    findings = _ip_findings('s.connect(("185.220.101.1", 80))', tmp_path)
    assert findings[0].layer is AnalysisLayer.REGEX


def test_ip_finding_lineno_correct(tmp_path: Path):
    source = 'x = 1\ns.connect(("185.220.101.1", 80))'
    findings = _ip_findings(source, tmp_path)
    assert findings[0].lineno == 2


# ---------------------------------------------------------------------------
# _is_private_ipv4 / _is_private_ipv6 unit tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",
        "172.16.0.1",
        "172.31.0.1",
        "192.168.1.1",
        "127.0.0.1",
    ],
)
def test_is_private_ipv4_returns_true(ip: str):
    assert _is_private_ipv4(ip) is True


@pytest.mark.parametrize(
    "ip",
    [
        "1.1.1.1",
        "8.8.8.8",
        "185.220.101.1",
        "203.0.113.1",
    ],
)
def test_is_private_ipv4_returns_false(ip: str):
    assert _is_private_ipv4(ip) is False


@pytest.mark.parametrize("ip", ["::1", "fe80::1", "fd00::1", "fc00::1"])
def test_is_private_ipv6_returns_true(ip: str):
    assert _is_private_ipv6(ip) is True


@pytest.mark.parametrize("ip", ["2606:4700::1111", "2001:db8::c2ef"])
def test_is_private_ipv6_returns_false(ip: str):
    assert _is_private_ipv6(ip) is False
