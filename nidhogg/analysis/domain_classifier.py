"""Domain threat classifier: categorise URLs by the threat profile of their host."""

from __future__ import annotations

import functools
import ipaddress
import tomllib
from importlib.resources import files
from urllib.parse import urlparse

from nidhogg.core.models import UrlTag

# Discord paths that indicate legitimate OAuth/invite usage (not data exfiltration).
_DISCORD_SAFE_PREFIXES = frozenset(["/invite/", "/oauth2/"])

# Categories that map a TOML section name to a UrlTag.
_SECTION_TO_TAG: dict[str, UrlTag] = {
    "shortener": UrlTag.SHORTENER,
    "tunneling": UrlTag.TUNNELING,
    "exfiltration": UrlTag.EXFILTRATION,
    "ip_recon": UrlTag.IP_RECON,
    "malware_hosting": UrlTag.MALWARE_HOSTING,
}


@functools.cache
def _load_data() -> dict[str, object]:
    """Load and cache suspicious_domains.toml from the package data directory.

    Returns:
        Parsed TOML document as a plain dict.
    """
    raw = (
        files("nidhogg")
        .joinpath("data")
        .joinpath("suspicious_domains.toml")
        .read_bytes()
    )
    return tomllib.loads(raw.decode("utf-8"))


def _host(url: str) -> str:
    """Extract the lowercased hostname from *url*, stripping any port number.

    Handles bracketed IPv6 addresses (``[::1]``) correctly by stripping the
    brackets before returning the bare address.

    Args:
        url: A URL string, optionally including scheme and port.

    Returns:
        The bare hostname in lowercase.
    """
    try:
        netloc = urlparse(url).netloc or url
    except ValueError:
        return ""
    # Bracketed IPv6: netloc is "[::1]" or "[::1]:port".
    if netloc.startswith("["):
        return netloc.split("]")[0].lstrip("[").lower()
    return netloc.lower().split(":")[0]


def _is_public_ip(hostname: str) -> bool:
    """Return ``True`` if *hostname* is a routable (public) IP address.

    Args:
        hostname: A string that may or may not be a valid IP address.

    Returns:
        ``True`` when the host is a public IPv4 or IPv6 address.
    """
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_unspecified
    )


def _is_punycode(hostname: str) -> bool:
    """Return ``True`` if any label of *hostname* is punycode-encoded (IDN).

    ``xn--`` labels decode to non-ASCII characters, which is how
    internationalised domains are transported in ASCII-only DNS. Attackers
    abuse this to register homograph lookalikes of trusted brands (e.g. a
    Cyrillic lookalike letter standing in for a Latin one), so any punycode
    label is treated as suspicious regardless of the decoded content.

    Args:
        hostname: Bare hostname, already lowercased.

    Returns:
        ``True`` when any dot-separated label starts with ``xn--``.
    """
    return any(label.startswith("xn--") for label in hostname.split("."))


def _match_section(
    hostname: str,
    path: str,
    section_data: dict[str, object],
    category: UrlTag,
) -> UrlTag | None:
    raw = section_data.get("domains", [])
    domains = raw if isinstance(raw, list) else []
    for domain in domains:
        if hostname == domain or hostname.endswith("." + domain):
            if domain == "discord.com" and any(
                path.startswith(p) for p in _DISCORD_SAFE_PREFIXES
            ):
                return None
            return category
    return None


def _match_suspicious_tld(hostname: str, tld_data: dict[str, object]) -> UrlTag | None:
    raw = tld_data.get("tlds", [])
    tlds = raw if isinstance(raw, list) else []
    for tld in tlds:
        if hostname.endswith(tld):
            return UrlTag.SUSPICIOUS_TLD
    return None


def classify_domain(url: str) -> set[UrlTag]:
    """Classify a URL by the threat tag(s) of its host.

    Evaluation order: public raw IP → punycode/IDN label → named category
    match (with the Discord ``/invite/`` and ``/oauth2/`` exception) →
    suspicious TLD suffix.

    Args:
        url: The URL to classify.

    Returns:
        A set with the matching :class:`UrlTag`, or an empty set if none.
    """
    hostname = _host(url)

    if _is_public_ip(hostname):
        return {UrlTag.RAW_IP}

    if _is_punycode(hostname):
        return {UrlTag.PUNYCODE}

    data = _load_data()
    try:
        path = urlparse(url).path
    except ValueError:
        path = ""

    for section, tag in _SECTION_TO_TAG.items():
        section_data = data.get(section)
        if isinstance(section_data, dict):
            result = _match_section(hostname, path, section_data, tag)
            if result is not None:
                return {result}

    tld_data = data.get("suspicious_tld")
    if isinstance(tld_data, dict):
        matched = _match_suspicious_tld(hostname, tld_data)
        if matched is not None:
            return {matched}

    return set()
