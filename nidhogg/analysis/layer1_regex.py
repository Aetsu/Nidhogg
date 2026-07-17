"""Layer 1: URL extraction via regular expressions over plain text."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from nidhogg.core.models import AnalysisLayer, UrlFinding, UrlTag

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# URL detection
# ---------------------------------------------------------------------------

# Matches http, https, ftp, ws, wss followed by anything that isn't
# whitespace, stopping right before another scheme starts so two URLs
# glued together without a separator (e.g. markdown badge links like
# `...svg)](https://...`) are captured as distinct matches instead of
# one merged string.  Trailing punctuation that is almost never part of
# a URL (quotes, brackets, commas, dots, and markdown's leftover `(`) is
# stripped afterwards.
_URL_RE = re.compile(r"(?:https?|ftp|wss?)://(?:(?!(?:https?|ftp|wss?)://)\S)+")


def _clean_url(raw: str) -> str:
    """Strip trailing punctuation that parsers routinely leave attached."""
    return raw.rstrip(".,;:'\"`!?()>]")


# ---------------------------------------------------------------------------
# IP detection
# ---------------------------------------------------------------------------

# Lines matching any of these patterns are considered network-call context.
_NET_CONTEXT_RE = re.compile(
    r"(?:"
    r"\bconnect\s*\("
    r"|\burlopen\s*\("
    r"|\brequests?\s*\.\s*(?:get|post|put|delete|head|patch|request)\s*\("
    r"|\bcreate_connection\s*\("
    r"|\bHTTPS?Connection\s*\("
    r")"
)

# Four decimal octets with optional port suffix.  Group 1 captures just the IP.
_IPV4_RE = re.compile(
    r"(?<![.\d])"
    r"(\d{1,3}(?:\.\d{1,3}){3})"
    r"(?::\d{1,5})?"
    r"(?![.\d])"
)

# One hex group (1-4 hex digits) reused throughout the IPv6 pattern.
_HEX4 = r"[0-9a-fA-F]{1,4}"

# Comprehensive IPv6 regex covering full (8-group) and all :: compressed forms.
# Negative lookarounds prevent matching inside longer hex sequences.
_IPV6_RE = re.compile(
    r"(?<![:\w])"
    rf"(?:(?:{_HEX4}:){{7}}{_HEX4}"  # full 8 groups
    rf"|(?:{_HEX4}:){{1,6}}:{_HEX4}"  # x…x::x
    rf"|(?:{_HEX4}:){{1,5}}(?::{_HEX4}){{1,2}}"  # x…x::x:x
    rf"|(?:{_HEX4}:){{1,4}}(?::{_HEX4}){{1,3}}"
    rf"|(?:{_HEX4}:){{1,3}}(?::{_HEX4}){{1,4}}"
    rf"|(?:{_HEX4}:){{1,2}}(?::{_HEX4}){{1,5}}"
    rf"|{_HEX4}:(?::{_HEX4}){{1,6}}"
    rf"|(?:{_HEX4}:){{1,7}}:"  # ends with ::
    rf"|:(?::{_HEX4}){{1,7}})"  # starts with :: (incl. ::1)
    r"(?![:\w])"
)


# RFC 1918 / RFC 5735 private and loopback first-octet constants.
_LOOPBACK_OCTET = 127
_RFC1918_10 = 10
_RFC1918_172 = 172
_RFC1918_172_MIN = 16
_RFC1918_172_MAX = 31
_RFC1918_192 = 192
_RFC1918_168 = 168
_IPV4_OCTET_COUNT = 4
_IPV4_MAX_OCTET = 255


def _is_private_ipv4(ip: str) -> bool:
    """Return ``True`` if *ip* falls within RFC 1918 or loopback ranges.

    Args:
        ip: Dotted-decimal IPv4 string without port.

    Returns:
        ``True`` when the address should be filtered out.
    """
    try:
        parts = [int(o) for o in ip.split(".")]
    except ValueError:
        return True
    if len(parts) != _IPV4_OCTET_COUNT or not all(
        0 <= p <= _IPV4_MAX_OCTET for p in parts
    ):
        return True
    a, b = parts[0], parts[1]
    return (
        a in {_LOOPBACK_OCTET, _RFC1918_10}  # 127.x / 10.x
        or (a == _RFC1918_172 and _RFC1918_172_MIN <= b <= _RFC1918_172_MAX)
        or (a == _RFC1918_192 and b == _RFC1918_168)  # 192.168.x
    )


def _is_private_ipv6(ip: str) -> bool:
    """Return ``True`` if *ip* is a loopback or link-local IPv6 address.

    Args:
        ip: IPv6 address string as matched by ``_IPV6_RE``.

    Returns:
        ``True`` when the address should be filtered out.
    """
    low = ip.lower()
    return low == "::1" or low.startswith(("fe80", "fc", "fd"))


def _extract_ips(source: str, filepath: Path) -> list[UrlFinding]:
    """Extract IP addresses found on lines containing network call context.

    Only lines that contain a recognisable connection-related call
    (``connect``, ``urlopen``, ``requests.get``, etc.) are scanned.
    IPs that are already part of a URL match are skipped to avoid
    double-reporting.  Private and loopback ranges are filtered out.

    Args:
        source: Raw text content of a Python source file.
        filepath: Path to the file being analysed (stored in findings).

    Returns:
        A list of :class:`UrlFinding` objects tagged with ``UrlTag.RAW_IP``.
    """
    findings: list[UrlFinding] = []
    for lineno, line in enumerate(source.splitlines(), start=1):
        if not _NET_CONTEXT_RE.search(line):
            continue

        # Spans of URL matches on this line — IPs inside them are already
        # reported by the URL regex and must not be double-counted.
        url_spans = [(m.start(), m.end()) for m in _URL_RE.finditer(line)]

        for m in _IPV4_RE.finditer(line):
            raw_ip = m.group(1)
            if any(start <= m.start() < end for start, end in url_spans):
                continue
            if _is_private_ipv4(raw_ip):
                continue
            findings.append(
                UrlFinding(
                    value=raw_ip,
                    filepath=filepath,
                    lineno=lineno,
                    layer=AnalysisLayer.REGEX,
                    tags={UrlTag.RAW_IP},
                )
            )

        for m in _IPV6_RE.finditer(line):
            raw_ip = m.group()
            if any(start <= m.start() < end for start, end in url_spans):
                continue
            if _is_private_ipv6(raw_ip):
                continue
            findings.append(
                UrlFinding(
                    value=raw_ip,
                    filepath=filepath,
                    lineno=lineno,
                    layer=AnalysisLayer.REGEX,
                    tags={UrlTag.RAW_IP},
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def extract_urls_regex(source: str, filepath: Path) -> list[UrlFinding]:
    """Extract URL and IP candidates from *source* using pattern matching.

    Scans every line of *source* for strings beginning with ``http``,
    ``https``, ``ftp``, ``ws``, or ``wss`` schemes.  Additionally detects
    raw IPv4 and IPv6 addresses on lines that contain network-call context
    (``connect``, ``urlopen``, ``requests.get``, etc.).

    Args:
        source: Raw text content of a Python source file.
        filepath: Path to the file being analysed (stored in findings).

    Returns:
        A list of :class:`UrlFinding` objects, one per URL or IP match.
    """
    findings: list[UrlFinding] = []

    for lineno, line in enumerate(source.splitlines(), start=1):
        for match in _URL_RE.finditer(line):
            url = _clean_url(match.group())
            findings.append(
                UrlFinding(
                    value=url,
                    filepath=filepath,
                    lineno=lineno,
                    layer=AnalysisLayer.REGEX,
                )
            )

    findings.extend(_extract_ips(source, filepath))
    return findings
