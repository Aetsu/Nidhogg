"""Tests for analysis/domain_classifier.py."""

from __future__ import annotations

import pytest

from nidhogg.analysis.domain_classifier import classify_domain
from nidhogg.core.models import UrlTag

# ---------------------------------------------------------------------------
# Named categories — one representative domain per category
# ---------------------------------------------------------------------------


def test_classify_shortener_domain():
    assert UrlTag.SHORTENER in classify_domain("https://bit.ly/3xyz")


def test_classify_shortener_subdomain():
    # Subdomain should also match.
    assert UrlTag.SHORTENER in classify_domain("https://sub.tinyurl.com/abc")


def test_classify_tunneling_domain():
    assert UrlTag.TUNNELING in classify_domain("https://abc.ngrok.io/endpoint")


def test_classify_tunneling_workers_dev():
    assert UrlTag.TUNNELING in classify_domain("https://myworker.workers.dev/api")


def test_classify_exfiltration_pastebin():
    assert UrlTag.EXFILTRATION in classify_domain("https://pastebin.com/raw/abc123")


def test_classify_exfiltration_webhook_site():
    assert UrlTag.EXFILTRATION in classify_domain("https://webhook.site/unique-id")


def test_classify_ip_recon_domain():
    assert UrlTag.IP_RECON in classify_domain("https://ipinfo.io/json")


def test_classify_ip_recon_ifconfig_me():
    assert UrlTag.IP_RECON in classify_domain("https://ifconfig.me")


def test_classify_malware_hosting_catbox():
    assert UrlTag.MALWARE_HOSTING in classify_domain(
        "https://files.catbox.moe/payload.exe"
    )


# ---------------------------------------------------------------------------
# Suspicious TLD
# ---------------------------------------------------------------------------


def test_classify_suspicious_tld_tk():
    assert UrlTag.SUSPICIOUS_TLD in classify_domain("https://evil.tk/download")


def test_classify_suspicious_tld_xyz():
    assert UrlTag.SUSPICIOUS_TLD in classify_domain("https://malware.xyz/")


def test_classify_suspicious_tld_zip():
    assert UrlTag.SUSPICIOUS_TLD in classify_domain("https://package.zip/file")


# ---------------------------------------------------------------------------
# Raw public IP
# ---------------------------------------------------------------------------


def test_classify_raw_ip_returns_raw_ip():
    # 8.8.8.8 is Google's public DNS — definitely a routable public IP.
    assert UrlTag.RAW_IP in classify_domain("https://8.8.8.8/cmd")


def test_classify_raw_ip_ipv6():
    # Cloudflare's public DNS resolver in standard bracketed IPv6 URL form.
    assert UrlTag.RAW_IP in classify_domain("http://[2606:4700:4700::1111]/shell")


def test_classify_private_ip_returns_none():
    # Private IPs are not flagged as RAW_IP.
    assert classify_domain("https://192.168.1.1/api") == set()


def test_classify_loopback_returns_none():
    assert classify_domain("https://127.0.0.1/api") == set()


# ---------------------------------------------------------------------------
# Discord special-case exceptions
# ---------------------------------------------------------------------------


def test_classify_discord_invite_returns_none():
    assert classify_domain("https://discord.com/invite/abc123") == set()


def test_classify_discord_oauth2_returns_none():
    assert classify_domain("https://discord.com/oauth2/authorize?client_id=1") == set()


def test_classify_discord_api_webhook_returns_exfiltration():
    assert UrlTag.EXFILTRATION in classify_domain(
        "https://discord.com/api/webhooks/123/token"
    )


def test_classify_discord_other_path_returns_exfiltration():
    assert UrlTag.EXFILTRATION in classify_domain(
        "https://discord.com/channels/123/456"
    )


# ---------------------------------------------------------------------------
# Unknown / benign domains
# ---------------------------------------------------------------------------


def test_classify_unknown_domain_returns_none():
    assert classify_domain("https://evil.example.com/beacon") == set()


def test_classify_benign_domain_returns_none():
    assert classify_domain("https://github.com/org/repo") == set()


@pytest.mark.parametrize(
    "url",
    [
        "https://api.openai.com/v1/completions",
        "https://pypi.org/project/requests",
        "https://docs.python.org/3/",
    ],
)
def test_classify_known_clean_domains_return_none(url: str):
    assert classify_domain(url) == set()


def test_public_ip_returns_raw_ip_tag() -> None:
    assert UrlTag.RAW_IP in classify_domain("http://8.8.8.8/x")


def test_unknown_domain_returns_empty_set() -> None:
    assert classify_domain("http://example.test/x") == set()
