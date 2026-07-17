"""HTTP-probe enrichment: fetch each URL's response status and page title.

This module issues a size-capped HTTP GET to each unique URL found in the
analysis, follows redirects, and records the final status code and the
cleaned page ``<title>`` as metadata on the finding for display purposes.
It is opt-in (requires network access) and never executes package code.
"""

from __future__ import annotations

import contextlib
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from loguru import logger

if TYPE_CHECKING:
    from nidhogg.core.models import FileAnalysis, UrlFinding

_TITLE_MAX_CHARS = 200
_MAX_BODY_BYTES = 64 * 1024
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)
_MAX_WORKERS = 10
_ANSI_ESCAPE_RE = re.compile(
    r"\x1b\[[0-9;?<=>]*[ -/]*[@-~]"  # CSI sequences, incl. private-mode ESC[?25l
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC sequences terminated by BEL or ST
    r"|\x1b."  # any other two-character escape
)


class _TitleParser(HTMLParser):
    """Collect the text content of the first ``<title>`` element."""

    def __init__(self) -> None:
        super().__init__()
        self._in_title = False
        self._done = False
        self._parts: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],  # noqa: ARG002
    ) -> None:
        if tag == "title" and not self._done:
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title" and self._in_title:
            self._in_title = False
            self._done = True

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._parts.append(data)

    @property
    def title(self) -> str:
        """Return the concatenated raw title text collected so far."""
        return "".join(self._parts)


def _extract_title(html_text: str) -> str | None:
    """Extract and clean the first ``<title>`` from *html_text*.

    Strips ANSI/CSI/OSC terminal escape sequences and any other non-printable
    control characters so a malicious page cannot inject escape sequences
    into the analyst's terminal, collapses runs of whitespace to single
    spaces, strips ends, and truncates to 200 characters.

    Args:
        html_text: Decoded HTML body.

    Returns:
        The cleaned title, or ``None`` when there is no non-empty ``<title>``.
    """
    parser = _TitleParser()
    with contextlib.suppress(Exception):
        parser.feed(html_text)
    no_escapes = _ANSI_ESCAPE_RE.sub("", parser.title)
    safe = "".join(c for c in no_escapes if c.isprintable() or c.isspace())
    cleaned = " ".join(safe.split())
    if not cleaned:
        return None
    return cleaned[:_TITLE_MAX_CHARS]


def _probe(url: str, *, timeout: float) -> tuple[int, str | None] | None:
    """Fetch *url* and return its final status code and cleaned page title.

    Issues an HTTP GET that follows redirects, reads at most
    ``_MAX_BODY_BYTES`` of the body, decodes it as UTF-8 (replacing invalid
    bytes), and extracts the ``<title>``. Never executes remote content.

    Args:
        url: Absolute http/https URL to request.
        timeout: Per-request timeout in seconds.

    Returns:
        ``(status, title)`` on any HTTP response (``title`` may be ``None``);
        ``None`` when no response is obtainable (timeout, connection error).
    """
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            status = int(resp.status)
            body = resp.read(_MAX_BODY_BYTES)
    except urllib.error.HTTPError as exc:
        logger.debug("HTTP probe {!r}: status {}", url, exc.code)
        return (int(exc.code), None)
    except Exception as exc:  # noqa: BLE001
        logger.debug("HTTP probe failed for {!r}: {}", url, exc)
        return None
    title = _extract_title(body.decode("utf-8", errors="replace"))
    return (status, title)


def check_urls(findings: list[UrlFinding], *, timeout: float = 5.0) -> list[UrlFinding]:
    """Probe each unique http/https URL in *findings* for status and title.

    Issues one GET per unique URL (concurrently), following redirects, and
    records the final status code and cleaned page title. Non-http(s) URLs
    and probe failures are silently skipped so the pipeline never blocks on
    network issues.

    Args:
        findings: Flattened URL findings (e.g. ``PackageAnalysis.findings``);
            mutated in place.
        timeout: Per-request timeout in seconds.

    Returns:
        The same list, with ``http_status``/``http_title`` populated for every
        finding whose URL returned an HTTP response.
    """
    url_to_findings: dict[str, list[UrlFinding]] = {}
    for finding in findings:
        try:
            parsed = urlparse(finding.value)
        except ValueError:
            continue
        if parsed.scheme not in ("http", "https"):
            continue
        url_to_findings.setdefault(finding.value, []).append(finding)

    if not url_to_findings:
        return findings

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        future_to_url = {
            pool.submit(_probe, url, timeout=timeout): url for url in url_to_findings
        }
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            probed = future.result()
            if probed is None:
                continue
            status, title = probed
            for f in url_to_findings[url]:
                f.http_status = status
                f.http_title = title

    return findings


def prune_unresponsive(files: list[FileAnalysis]) -> list[FileAnalysis]:
    """Drop http/https findings that got no response from :func:`check_urls`.

    Findings for non-http(s) schemes (never probed) are left untouched.

    Args:
        files: Per-file analyses whose findings have already been probed by
            :func:`check_urls`. Mutated in place.

    Returns:
        The same list, with each file's findings filtered.
    """
    for fa in files:
        fa.findings = [
            f
            for f in fa.findings
            if f.http_status is not None
            or urlparse(f.value).scheme not in ("http", "https")
        ]
    return files
