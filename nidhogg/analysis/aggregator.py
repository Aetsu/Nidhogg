"""Aggregator: deduplication and normalisation of URL findings."""

from __future__ import annotations

import dataclasses
import ipaddress
import re
from importlib.resources import files
from typing import TYPE_CHECKING
from urllib.parse import urlparse, urlunparse

from nidhogg.analysis.domain_classifier import classify_domain

if TYPE_CHECKING:
    from pathlib import Path

    from nidhogg.core.models import FileAnalysis, UrlFinding


def _parse_domain_lines(text: str) -> frozenset[str]:
    """Parse domain lines from plain text, skipping comments and blanks.

    Args:
        text: File contents with one domain per line. Lines starting with
            ``#`` are treated as comments and ignored.

    Returns:
        A frozenset of stripped domain names.
    """
    return frozenset(
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


def _load_default_benign_domains() -> frozenset[str]:
    """Load the benign domain list bundled with the package.

    Returns:
        A frozenset of domain names to treat as benign.
    """
    text = (
        files("nidhogg")
        .joinpath("data")
        .joinpath("benign_domains.txt")
        .read_text(encoding="utf-8")
    )
    return _parse_domain_lines(text)


def load_benign_domains(path: Path) -> frozenset[str]:
    """Load a benign domain list from an arbitrary file path.

    Lines starting with ``#`` are treated as comments and ignored.
    Empty lines are skipped.

    Args:
        path: Path to a plain-text file with one domain per line.

    Returns:
        A frozenset of domain names to treat as benign.
    """
    return _parse_domain_lines(path.read_text(encoding="utf-8"))


_BENIGN_DOMAINS: frozenset[str] = _load_default_benign_domains()

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_INVALID_URL_CHARS_RE = re.compile(r"[^\x20-\x7e]")
_INVALID_HOST_CHARS_RE = re.compile(r"[{}|\\^`\"'()\s]")


def _clean_url(url: str) -> str:
    """Remove invalid and control characters from *url*.

    Strips control characters (ASCII 0-31, 127) and non-ASCII characters
    that are not valid in URLs. Replaces spaces with ``%20``.

    Args:
        url: Raw URL string potentially containing invalid characters.

    Returns:
        The cleaned URL string.
    """
    cleaned = _CONTROL_CHARS_RE.sub("", url)
    cleaned = _INVALID_URL_CHARS_RE.sub("", cleaned)
    return cleaned.replace(" ", "%20")


def _is_valid_url(url: str) -> bool:
    """Return ``True`` if *url* is a valid, well-formed URL.

    Checks that the URL has a valid scheme and network location (host).
    Rejects URLs with missing or malformed components, or with invalid
    characters in the host.

    Args:
        url: URL string to validate.

    Returns:
        ``True`` when the URL is structurally valid.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if not parsed.scheme or not parsed.netloc:
        return False
    if parsed.scheme not in {"http", "https", "ftp", "ws", "wss"}:
        return False
    host = parsed.netloc.split(":")[0]
    if not host:
        return False
    return not _INVALID_HOST_CHARS_RE.search(host)


def _normalize(url: str) -> str:
    """Normalize *url* for stable deduplication.

    Lowercases the domain, strips the fragment, and removes a trailing slash
    from the path.

    Args:
        url: Raw URL string as extracted by an analysis layer.

    Returns:
        The normalised URL string.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return url
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc.lower(),
            parsed.path.rstrip("/"),
            parsed.params,
            parsed.query,
            "",  # discard fragment
        )
    )


def _is_benign(url: str, benign_domains: frozenset[str]) -> bool:
    """Return ``True`` if *url*'s host matches any entry in *benign_domains*.

    Matches the exact domain and any subdomain
    (e.g. ``files.pypi.org`` is matched by ``pypi.org``).

    Args:
        url: Normalised URL string.
        benign_domains: Set of domain names to treat as benign.

    Returns:
        ``True`` when the URL should be filtered out.
    """
    try:
        host = urlparse(url).netloc.lower().split(":")[0]
    except ValueError:
        return False
    return any(
        host == domain or host.endswith("." + domain) for domain in benign_domains
    )


def _is_non_public_ip(url: str) -> bool:
    """Return ``True`` if *url*'s host is a non-public IP address.

    Detects private, loopback, link-local, reserved, and unspecified
    addresses for both IPv4 and IPv6.  Returns ``False`` for domain names
    and for public IP addresses.

    Args:
        url: Normalised URL string.

    Returns:
        ``True`` when the URL should be filtered out because its host is
        a non-routable IP.
    """
    try:
        netloc = urlparse(url).netloc.lower()
    except ValueError:
        return False
    if netloc.startswith("["):
        host = netloc.lstrip("[").split("]")[0]
    else:
        host = netloc.split(":")[0]
    if not host:
        return False
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_unspecified
    )


def _aggregate_findings(
    findings: list[UrlFinding],
    benign_domains: frozenset[str],
) -> list[UrlFinding]:
    """Clean, filter, dedup (by value+line, merging tags) and tag *findings*.

    Args:
        findings: Raw findings from a single file.
        benign_domains: Domain names to treat as benign and drop.

    Returns:
        The deduplicated, normalised, threat-tagged findings for the file.
    """
    seen: dict[tuple[str, int], UrlFinding] = {}
    for finding in findings:
        cleaned_url = _clean_url(finding.value)
        if not _is_valid_url(cleaned_url):
            continue
        normalized_url = _normalize(cleaned_url)
        if _is_benign(normalized_url, benign_domains):
            continue
        if _is_non_public_ip(normalized_url):
            continue
        key = (normalized_url, finding.lineno)
        if key in seen:
            seen[key].tags |= finding.tags
        else:
            seen[key] = dataclasses.replace(
                finding, value=normalized_url, tags=set(finding.tags)
            )

    result: list[UrlFinding] = []
    for finding in seen.values():
        finding.tags |= classify_domain(finding.value)
        result.append(finding)
    return result


def aggregate(
    files: list[FileAnalysis],
    *,
    benign_domains: frozenset[str] = _BENIGN_DOMAINS,
) -> list[FileAnalysis]:
    """Deduplicate, normalise, filter, and threat-tag findings, per file.

    Within each file, duplicate URLs (same normalised value on the same line)
    are merged into one finding whose tag set is the union of the duplicates.
    Domain threat tags are attached from :func:`classify_domain`. URLs whose
    host is benign or a non-public IP are dropped. File tags are preserved.

    Args:
        files: Per-file analyses straight from the walker.
        benign_domains: Domain names to treat as benign and filter out.

    Returns:
        New :class:`FileAnalysis` objects with aggregated findings.
    """
    return [
        dataclasses.replace(
            fa,
            findings=_aggregate_findings(fa.findings, benign_domains),
            tags=set(fa.tags),
        )
        for fa in files
    ]
