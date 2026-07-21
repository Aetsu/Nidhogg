"""Tests for analysis/aggregator.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from nidhogg.analysis.aggregator import (
    _BENIGN_DOMAINS,
    _clean_url,
    _is_benign,
    _is_non_public_ip,
    _is_valid_url,
    _normalize,
    aggregate,
    load_benign_domains,
)
from nidhogg.core.models import AnalysisLayer, FileAnalysis, FileTag, UrlFinding, UrlTag


def _finding(
    url: str,
    lineno: int = 1,
    layer: AnalysisLayer = AnalysisLayer.AST,
    filepath: Path | None = None,
) -> UrlFinding:
    return UrlFinding(
        value=url,
        filepath=filepath or Path("/fake/file.py"),
        lineno=lineno,
        layer=layer,
    )


def _aggregate_findings_only(
    findings: list[UrlFinding],
    benign_domains: frozenset[str] = _BENIGN_DOMAINS,
) -> list[UrlFinding]:
    """Run aggregate() on a single synthetic file and return its findings."""
    fa = FileAnalysis(filepath=Path("/fake/file.py"), findings=findings)
    result = aggregate([fa], benign_domains=benign_domains)
    return result[0].findings if result else []


# ---------------------------------------------------------------------------
# _normalize
# ---------------------------------------------------------------------------


def test_normalize_lowercases_domain():
    assert _normalize("https://EVIL.TEST.COM/path") == "https://evil.test.com/path"


def test_normalize_strips_fragment():
    assert _normalize("https://evil.test/path#section") == "https://evil.test/path"


def test_normalize_strips_trailing_slash():
    assert _normalize("https://evil.test/path/") == "https://evil.test/path"


def test_normalize_preserves_query():
    result = _normalize("https://evil.test/path?key=val")
    assert "key=val" in result


def test_normalize_idempotent():
    url = "https://evil.test/path"
    assert _normalize(_normalize(url)) == _normalize(url)


def test_normalize_empty_path_no_trailing_slash():
    # Root path — no slash left after rstrip
    result = _normalize("https://evil.test/")
    assert not result.endswith("/")


# ---------------------------------------------------------------------------
# _clean_url
# ---------------------------------------------------------------------------


def test_clean_url_removes_control_characters():
    assert _clean_url("https://evil.com/\x00path") == "https://evil.com/path"
    assert _clean_url("https://evil.com/\x1fpath") == "https://evil.com/path"
    assert _clean_url("https://evil.com/\x7fpath") == "https://evil.com/path"


def test_clean_url_removes_non_ascii_characters():
    assert _clean_url("https://evil.com/páth") == "https://evil.com/pth"
    assert _clean_url("https://evil.com/path\x80") == "https://evil.com/path"


def test_clean_url_replaces_spaces_with_percent20():
    assert _clean_url("https://evil.com/my path") == "https://evil.com/my%20path"


def test_clean_url_preserves_valid_url():
    url = "https://evil.test/path?query=value&other=123"
    assert _clean_url(url) == url


def test_clean_url_handles_multiple_issues():
    assert (
        _clean_url("https://evil.com/\x00my path\x1f") == "https://evil.com/my%20path"
    )


# ---------------------------------------------------------------------------
# _is_valid_url
# ---------------------------------------------------------------------------


def test_is_valid_url_accepts_http():
    assert _is_valid_url("http://evil.com/path") is True


def test_is_valid_url_accepts_https():
    assert _is_valid_url("https://evil.com/path") is True


def test_is_valid_url_accepts_ftp():
    assert _is_valid_url("ftp://files.com/data") is True


def test_is_valid_url_accepts_ws():
    assert _is_valid_url("ws://socket.com/ws") is True


def test_is_valid_url_accepts_wss():
    assert _is_valid_url("wss://secure.com/ws") is True


def test_is_valid_url_rejects_missing_scheme():
    assert _is_valid_url("evil.com/path") is False


def test_is_valid_url_rejects_missing_netloc():
    assert _is_valid_url("http://") is False
    assert _is_valid_url("https:///path") is False


def test_is_valid_url_rejects_invalid_scheme():
    assert _is_valid_url("javascript://alert(1)") is False
    assert _is_valid_url("file:///etc/passwd") is False


def test_is_valid_url_rejects_empty_string():
    assert _is_valid_url("") is False


def test_is_valid_url_rejects_malformed_url():
    assert _is_valid_url("://missing-scheme") is False


def test_is_valid_url_accepts_url_with_port():
    assert _is_valid_url("https://evil.com:8080/path") is True


def test_is_valid_url_accepts_url_with_credentials():
    assert _is_valid_url("https://user:pass@evil.com/path") is True


def test_is_valid_url_rejects_curly_braces_in_host():
    assert _is_valid_url("https://{host}/path") is False
    assert _is_valid_url("https://{_host}/exfiltrate") is False


def test_is_valid_url_rejects_backtick_in_host():
    assert _is_valid_url("https://evil`test.com/path") is False


def test_is_valid_url_rejects_pipe_in_host():
    assert _is_valid_url("https://evil|test.com/path") is False


def test_is_valid_url_rejects_quotes_in_host():
    assert _is_valid_url('wss://").replace("http:') is False
    assert _is_valid_url('https://evil"test.com/path') is False
    assert _is_valid_url("https://evil'test.com/path") is False


def test_is_valid_url_rejects_parens_in_host():
    assert _is_valid_url("https://evil(test).com/path") is False


# ---------------------------------------------------------------------------
# aggregate — URL cleaning and validation
# ---------------------------------------------------------------------------


def test_aggregate_cleans_urls_with_control_chars():
    findings = [_finding("https://evil.com/\x00path")]
    result = _aggregate_findings_only(findings)
    assert len(result) == 1
    assert result[0].value == "https://evil.com/path"


def test_aggregate_cleans_urls_with_spaces():
    findings = [_finding("https://evil.com/my path")]
    result = _aggregate_findings_only(findings)
    assert len(result) == 1
    assert result[0].value == "https://evil.com/my%20path"


def test_aggregate_filters_invalid_urls_missing_scheme():
    findings = [_finding("evil.com/path")]
    result = _aggregate_findings_only(findings)
    assert len(result) == 0


def test_aggregate_filters_invalid_urls_missing_netloc():
    findings = [_finding("http://")]
    result = _aggregate_findings_only(findings)
    assert len(result) == 0


def test_aggregate_filters_invalid_urls_invalid_scheme():
    findings = [_finding("javascript://alert(1)")]
    result = _aggregate_findings_only(findings)
    assert len(result) == 0


def test_aggregate_keeps_valid_urls_and_filters_invalid():
    findings = [
        _finding("https://evil.com/valid"),
        _finding("invalid-url"),
        _finding("https://other.com/also-valid"),
    ]
    result = _aggregate_findings_only(findings)
    assert len(result) == 2
    assert all("evil.com" in r.value or "other.com" in r.value for r in result)


def test_aggregate_cleans_then_validates():
    # URL that becomes valid after cleaning
    findings = [_finding("https://evil.com/\x00path")]
    result = _aggregate_findings_only(findings)
    assert len(result) == 1


def test_aggregate_cleans_then_rejects():
    # URL that remains invalid even after cleaning
    findings = [_finding("\x00\x1f\x7f")]
    result = _aggregate_findings_only(findings)
    assert len(result) == 0


# ---------------------------------------------------------------------------
# _is_benign
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://pypi.org/project/requests",
        "https://files.pypi.org/packages/foo.tar.gz",
        "https://python.org/docs",
        "https://www.python.org/ftp/python",
        "https://raw.githubusercontent.com/user/repo/file.py",
    ],
)
def test_is_benign_known_domains(url: str):
    assert _is_benign(url, _BENIGN_DOMAINS) is True


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.test/beacon",
        "https://c2.attacker.net/exfil",
        "https://notpypi.org/project",
    ],
)
def test_is_benign_unknown_domains(url: str):
    assert _is_benign(url, _BENIGN_DOMAINS) is False


def test_is_benign_custom_domain_set():
    custom = frozenset({"internal.corp"})
    assert _is_benign("https://internal.corp/api", custom) is True
    assert _is_benign("https://pypi.org/project", custom) is False


# ---------------------------------------------------------------------------
# aggregate — deduplication
# ---------------------------------------------------------------------------


def test_aggregate_empty_input():
    assert aggregate([]) == []


def test_aggregate_single_finding():
    f = _finding("https://evil.test/path")
    result = _aggregate_findings_only([f])
    assert len(result) == 1
    assert result[0].value == "https://evil.test/path"


def test_aggregate_deduplicates_identical_urls():
    findings = [
        _finding("https://evil.test/path"),
        _finding("https://evil.test/path"),
    ]
    result = _aggregate_findings_only(findings)
    assert len(result) == 1


def test_aggregate_distinct_urls_both_kept():
    findings = [
        _finding("https://evil.test/a"),
        _finding("https://evil.test/b"),
    ]
    result = _aggregate_findings_only(findings)
    assert len(result) == 2


# ---------------------------------------------------------------------------
# aggregate — normalisation applied to deduplication
# ---------------------------------------------------------------------------


def test_aggregate_deduplicates_after_domain_lowercase():
    findings = [
        _finding("https://EVIL.TEST.COM/path"),
        _finding("https://evil.test.com/path"),
    ]
    result = _aggregate_findings_only(findings)
    assert len(result) == 1
    assert result[0].value == "https://evil.test.com/path"


def test_aggregate_deduplicates_url_differing_only_by_fragment():
    findings = [
        _finding("https://evil.test/path#section1"),
        _finding("https://evil.test/path#section2"),
    ]
    result = _aggregate_findings_only(findings)
    assert len(result) == 1


def test_aggregate_deduplicates_trailing_slash():
    findings = [
        _finding("https://evil.test/path/"),
        _finding("https://evil.test/path"),
    ]
    result = _aggregate_findings_only(findings)
    assert len(result) == 1


def test_aggregate_normalized_value_stored():
    f = _finding("https://EVIL.TEST.COM/path/")
    result = _aggregate_findings_only([f])
    assert result[0].value == "https://evil.test.com/path"


# ---------------------------------------------------------------------------
# aggregate — benign filtering
# ---------------------------------------------------------------------------


def test_aggregate_filters_pypi_org():
    findings = [
        _finding("https://pypi.org/project/requests"),
        _finding("https://evil.test/beacon"),
    ]
    result = _aggregate_findings_only(findings)
    assert len(result) == 1
    assert "evil.test" in result[0].value


def test_aggregate_filters_python_org():
    assert _aggregate_findings_only([_finding("https://python.org/docs")]) == []


def test_aggregate_filters_githubusercontent():
    assert (
        _aggregate_findings_only(
            [_finding("https://raw.githubusercontent.com/u/r/f.py")]
        )
        == []
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost",
        "https://localhost",
        "http://localhost:8080",
        "https://localhost:443/api/v1",
        "http://localhost:3000/webhook",
        "ftp://localhost/pub",
    ],
)
def test_aggregate_filters_localhost(url: str):
    assert _aggregate_findings_only([_finding(url)]) == []


def test_aggregate_custom_benign_domains():
    findings = [
        _finding("https://trusted.internal/api"),
        _finding("https://evil.test/beacon"),
    ]
    result = _aggregate_findings_only(
        findings, benign_domains=frozenset({"trusted.internal"})
    )
    assert len(result) == 1
    assert "evil.test" in result[0].value


def test_aggregate_empty_benign_domains_keeps_all():
    findings = [
        _finding("https://pypi.org/project/requests"),
        _finding("https://evil.test/beacon"),
    ]
    result = _aggregate_findings_only(findings, benign_domains=frozenset())
    assert len(result) == 2


# ---------------------------------------------------------------------------
# _BENIGN_DOMAINS — coverage of the bundled list
# ---------------------------------------------------------------------------


def test_benign_domains_has_at_least_100_entries():
    assert len(_BENIGN_DOMAINS) >= 100


@pytest.mark.parametrize(
    "url",
    [
        # CDNs
        "https://cdn.jsdelivr.net/npm/foo",
        "https://sub.fastly.net/assets/bar.js",
        "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js",
        # Cloud providers
        "https://mybucket.s3.amazonaws.com/key",
        "https://storage.googleapis.com/bucket/object",
        "https://myapp.azurewebsites.net",
        "https://d111111abcdef8.cloudfront.net/path",
        # Monitoring / telemetry
        "https://o123456.ingest.sentry.io/api/1234/store/",
        "https://intake.datadoghq.com/api/v2/logs",
        "https://api.honeycomb.io/1/batch/dataset",
        # CI / CD
        "https://api.travis-ci.com/repo/123/builds",
        "https://app.circleci.com/pipelines/github/org/repo",
        "https://codecov.io/gh/org/repo",
        # Messaging / email
        "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXX",
        "https://api.sendgrid.com/v3/mail/send",
        "https://api.mailgun.net/v3/domain/messages",
        # Auth
        "https://tenant.auth0.com/oauth/token",
        "https://myorg.okta.com/api/v1/authn",
        # Static hosting
        "https://myapp.netlify.app/index.html",
        "https://myapp.vercel.app/_next/static/chunks/main.js",
        # Container registries
        "https://ghcr.io/owner/image:tag",
        "https://quay.io/repository/org/image",
        # Community
        "https://stackoverflow.com/questions/123",
        "https://apache.org/licenses/LICENSE-2.0",
    ],
)
def test_is_benign_bundled_domains(url: str):
    assert _is_benign(url, _BENIGN_DOMAINS) is True


# ---------------------------------------------------------------------------
# Subdomain wildcard coverage for new domains
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://files.pypi.org/packages/foo.tar.gz",
        "https://eu.api.mailgun.net/v3/domain/messages",
        "https://eu.rollbar.com/api/1/item/",
        "https://my-org.sentry.io/api/0/projects/",
        "https://sub.netlify.com/path",
    ],
)
def test_is_benign_subdomain_wildcard(url: str):
    assert _is_benign(url, _BENIGN_DOMAINS) is True


# ---------------------------------------------------------------------------
# Curated docs / standards / OSS project domains (#6)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://specifications.freedesktop.org/secret-service/latest",
        "https://systemd.io/CREDENTIALS",
        "https://everything.curl.dev/usingcurl/netrc.html",
        "https://curl.se/docs/manpage.html",
        "https://www.kernel.org/doc/html/latest/",
        "https://man7.org/linux/man-pages/man2/open.2.html",
        "https://doc.rust-lang.org/std/",
        "https://llvm.org/docs/LangRef.html",
        "https://cmake.org/cmake/help/latest/",
        "https://www.sqlite.org/lang.html",
        "https://www.openssl.org/docs/",
        "https://www.postgresql.org/docs/current/",
        "https://nginx.org/en/docs/",
    ],
)
def test_is_benign_curated_docs_domains(url: str):
    assert _is_benign(url, _BENIGN_DOMAINS) is True


# ---------------------------------------------------------------------------
# load_benign_domains — public loader for custom files
# ---------------------------------------------------------------------------


def test_load_benign_domains_reads_file(tmp_path: Path):
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("trusted.internal\ncorp.example.com\n", encoding="utf-8")
    result = load_benign_domains(domains_file)
    assert result == frozenset({"trusted.internal", "corp.example.com"})


def test_load_benign_domains_skips_comments(tmp_path: Path):
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text(
        "# This is a comment\ntrusted.internal\n# Another comment\ncorp.example.com\n",
        encoding="utf-8",
    )
    result = load_benign_domains(domains_file)
    assert result == frozenset({"trusted.internal", "corp.example.com"})


def test_load_benign_domains_skips_blank_lines(tmp_path: Path):
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text(
        "\ntrusted.internal\n\ncorp.example.com\n\n", encoding="utf-8"
    )
    result = load_benign_domains(domains_file)
    assert result == frozenset({"trusted.internal", "corp.example.com"})


def test_load_benign_domains_empty_file(tmp_path: Path):
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("", encoding="utf-8")
    assert load_benign_domains(domains_file) == frozenset()


def test_aggregate_with_custom_benign_file(tmp_path: Path):
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("trusted.internal\n", encoding="utf-8")
    findings = [
        _finding("https://trusted.internal/api"),
        _finding("https://evil.test/beacon"),
    ]
    result = _aggregate_findings_only(
        findings, benign_domains=load_benign_domains(domains_file)
    )
    assert len(result) == 1
    assert "evil.test" in result[0].value


# ---------------------------------------------------------------------------
# domain tag classification
# ---------------------------------------------------------------------------


def test_aggregate_attaches_shortener_tag():
    result = _aggregate_findings_only([_finding("https://bit.ly/3xyz")])
    assert UrlTag.SHORTENER in result[0].tags


def test_aggregate_no_domain_tag_for_unknown_domain():
    result = _aggregate_findings_only([_finding("https://evil.test/beacon")])
    assert result[0].tags == set()


# ---------------------------------------------------------------------------
# _is_non_public_ip
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1",
        "http://127.0.0.1:8787",
        "https://127.0.0.1:443/api",
        "http://10.0.0.1/internal",
        "http://172.16.0.1/data",
        "http://192.168.1.1/admin",
        "http://0.0.0.0",
        "http://169.254.169.254/latest/meta-data",
        "http://[::1]",
        "http://[::1]:8080",
        "http://[fe80::1]",
        "http://[fc00::1]",
    ],
)
def test_is_non_public_ip_private_addresses(url: str):
    assert _is_non_public_ip(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.test/beacon",
        "https://8.8.8.8/dns",
        "https://1.1.1.1/dns",
        "http://localhost",
    ],
)
def test_is_non_public_ip_public_or_domain(url: str):
    assert _is_non_public_ip(url) is False


# ---------------------------------------------------------------------------
# aggregate — non-public IP filtering
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8787",
        "http://127.0.0.1",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/admin",
        "http://[::1]:8080",
    ],
)
def test_aggregate_filters_non_public_ip_urls(url: str):
    assert _aggregate_findings_only([_finding(url)]) == []


def test_aggregate_filters_non_public_ip_keeps_public():
    findings = [
        _finding("http://127.0.0.1:8787"),
        _finding("https://8.8.8.8/dns"),
        _finding("https://evil.test/beacon"),
    ]
    result = _aggregate_findings_only(findings)
    assert len(result) == 2
    assert all("127.0.0.1" not in r.value for r in result)


# ---------------------------------------------------------------------------
# aggregate — per-file operation: preserved file tags, tag merging, domain tags
# ---------------------------------------------------------------------------


def test_aggregate_preserves_file_tags() -> None:
    fa = FileAnalysis(
        filepath=Path("README.md"),
        tags={FileTag.README},
        findings=[
            UrlFinding("http://evil.test/x", Path("README.md"), 1, AnalysisLayer.REGEX)
        ],
    )
    result = aggregate([fa])
    assert result[0].tags == {FileTag.README}


def test_aggregate_merges_tags_of_same_url_same_line() -> None:
    fp = Path("a.py")
    fa = FileAnalysis(
        filepath=fp,
        findings=[
            UrlFinding("http://evil.test/x", fp, 3, AnalysisLayer.REGEX, set()),
            UrlFinding(
                "http://evil.test/x", fp, 3, AnalysisLayer.AST, {UrlTag.VIA_CONCAT}
            ),
        ],
    )
    result = aggregate([fa])
    assert len(result[0].findings) == 1
    assert UrlTag.VIA_CONCAT in result[0].findings[0].tags


def test_aggregate_same_url_different_lines_kept_separately() -> None:
    fp = Path("a.py")
    fa = FileAnalysis(
        filepath=fp,
        findings=[
            UrlFinding("http://evil.test/x", fp, 3, AnalysisLayer.REGEX, set()),
            UrlFinding("http://evil.test/x", fp, 7, AnalysisLayer.REGEX, set()),
        ],
    )
    result = aggregate([fa])
    assert len(result[0].findings) == 2


def test_aggregate_attaches_domain_tag() -> None:
    fp = Path("a.py")
    fa = FileAnalysis(
        filepath=fp,
        findings=[
            UrlFinding("http://8.8.8.8/x", fp, 1, AnalysisLayer.REGEX, {UrlTag.RAW_IP})
        ],
    )
    result = aggregate([fa])
    assert UrlTag.RAW_IP in result[0].findings[0].tags
