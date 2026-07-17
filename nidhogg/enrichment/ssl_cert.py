"""SSL certificate enrichment: read TLS certificate issuer for HTTPS domains.

This module connects to each unique HTTPS domain found in the analysis
and reads the TLS certificate issuer organisation. The issuer is stored
as metadata on the finding for display purposes.
"""

from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from loguru import logger

if TYPE_CHECKING:
    from nidhogg.core.models import UrlFinding

_SSL_PORT = 443
_MAX_WORKERS = 10


def _get_cert_issuer(hostname: str, *, timeout: float) -> str | None:
    """Fetch the issuer organisation name from the TLS certificate of *hostname*.

    Connects to port 443 and reads the ``organizationName`` field from the
    certificate's issuer distinguished name.

    Args:
        hostname: DNS name to connect to on port 443.
        timeout: Connection timeout in seconds.

    Returns:
        The ``organizationName`` value from the certificate issuer, or
        ``None`` when the connection fails or the field is absent.
    """
    ctx = ssl.create_default_context()
    try:
        with (
            socket.create_connection((hostname, _SSL_PORT), timeout=timeout) as raw,
            ctx.wrap_socket(raw, server_hostname=hostname) as tls,
        ):
            cert = tls.getpeercert()
    except Exception as exc:  # noqa: BLE001
        logger.debug("SSL check failed for {!r}: {}", hostname, exc)
        return None
    if cert is None:
        return None
    for rdn in cert.get("issuer", ()):
        for key, value in rdn:  # type: ignore[misc]  # ssl returns runtime tuples typed as Any
            if key == "organizationName":
                return str(value)
    return None


def check_certificates(
    findings: list[UrlFinding], *, timeout: float = 3.0
) -> list[UrlFinding]:
    """Check TLS certificates for each unique HTTPS domain in *findings*.

    Connects to port 443 of each unique domain and reads the certificate
    issuer. Non-HTTPS URLs and connection failures are silently skipped
    so the pipeline never blocks on network issues.

    Args:
        findings: Flattened URL findings (e.g. ``PackageAnalysis.findings``);
            mutated in place.
        timeout: Per-host TCP connection timeout in seconds.

    Returns:
        The same list, with ``cert_issuer`` populated for every finding
        whose domain serves HTTPS.
    """
    hostname_to_findings: dict[str, list[UrlFinding]] = {}
    for finding in findings:
        try:
            parsed = urlparse(finding.value)
        except ValueError:
            continue
        if parsed.scheme != "https" or not parsed.hostname:
            continue
        hostname_to_findings.setdefault(parsed.hostname, []).append(finding)

    if not hostname_to_findings:
        return findings

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        future_to_host = {
            pool.submit(_get_cert_issuer, h, timeout=timeout): h
            for h in hostname_to_findings
        }
        for future in as_completed(future_to_host):
            hostname = future_to_host[future]
            issuer = future.result()
            if issuer is None:
                continue
            for f in hostname_to_findings[hostname]:
                f.cert_issuer = issuer
                logger.debug(
                    "Certificate for {!r}: issuer={!r} ({}:{})",
                    hostname,
                    issuer,
                    f.filepath.name,
                    f.lineno,
                )

    return findings
