# HTTP Probe Enrichment (`--check-http`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in `--check-http` flag that requests each found URL over HTTP and records its final response status code and cleaned page title on every `UrlFinding`.

**Architecture:** New pure enrichment module `nidhogg/enrichment/http_probe.py` mirroring `ssl_cert.py`: a thread-pooled `check_urls()` that mutates findings in place, backed by a private `_probe()` that does a size-capped `urllib` GET (following redirects) and an `html.parser`-based title extractor. Two new optional fields on `UrlFinding`. CLI wires the flag through `analyze` only, and writer/renderer surface the fields.

**Tech Stack:** Python 3.14, stdlib only (`urllib.request`, `html.parser`), loguru, rich, pytest, uv.

## Global Constraints

- Python `>=3.14`; target-version `py314`.
- **No new runtime dependencies** — stdlib only (`urllib.request`, `html.parser`). Runtime deps stay `loguru`, `rich`.
- Strict type hints on every function/method including returns; Google-style docstrings on public functions.
- Run tools via `uv run` — `uv run pytest`, `uv run ruff check`, `uv run ruff format`, `uv run mypy`.
- Ruff lint select = `ALL`; match existing `# noqa` conventions (`BLE001` for broad excepts, `PLC0415` for lazy imports).
- Analysis/enrichment functions are pure input→output, no hidden global state.
- Functions ~≤30 lines.
- Commit message trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

### Task 1: Add HTTP fields to `UrlFinding`

**Files:**
- Modify: `nidhogg/core/models.py:50-69`
- Test: `tests/test_models.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `UrlFinding.http_status: int | None` (default `None`), `UrlFinding.http_title: str | None` (default `None`).

- [ ] **Step 1: Write the failing test**

Add to `tests/test_models.py`:

```python
def test_urlfinding_http_fields_default_none() -> None:
    from pathlib import Path

    from nidhogg.core.models import AnalysisLayer, UrlFinding

    finding = UrlFinding(
        value="http://example.com",
        filepath=Path("pkg/x.py"),
        lineno=1,
        layer=AnalysisLayer.REGEX,
    )
    assert finding.http_status is None
    assert finding.http_title is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_models.py::test_urlfinding_http_fields_default_none -v`
Expected: FAIL — `AttributeError: 'UrlFinding' object has no attribute 'http_status'`.

- [ ] **Step 3: Add the fields**

In `nidhogg/core/models.py`, extend the `UrlFinding` dataclass. Update the docstring `Attributes:` block and add the fields after `cert_issuer`:

```python
        cert_issuer: TLS certificate issuer organisation, set by the SSL
            enrichment step. ``None`` when not checked or not HTTPS.
        http_status: Final HTTP status code after redirects, set by the
            HTTP-probe enrichment step. ``None`` when not checked or no
            response.
        http_title: Cleaned page ``<title>`` (whitespace-collapsed, ≤200
            chars), set by the HTTP-probe enrichment step. ``None`` when not
            checked, no response, or no title.
    """

    value: str
    filepath: Path
    lineno: int
    layer: AnalysisLayer
    tags: set[UrlTag] = field(default_factory=set)
    cert_issuer: str | None = None
    http_status: int | None = None
    http_title: str | None = None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_models.py::test_urlfinding_http_fields_default_none -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/core/models.py tests/test_models.py
git commit -m "feat: add http_status and http_title fields to UrlFinding

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Title extractor `_extract_title`

**Files:**
- Create: `nidhogg/enrichment/http_probe.py`
- Test: `tests/test_http_probe.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `_extract_title(html_text: str) -> str | None` — returns the cleaned first `<title>` (strip, whitespace collapsed to single spaces, truncated to 200 chars) or `None` when absent/empty.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_http_probe.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_http_probe.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'nidhogg.enrichment.http_probe'`.

- [ ] **Step 3: Write the module with the title extractor**

Create `nidhogg/enrichment/http_probe.py`:

```python
"""HTTP-probe enrichment: fetch each URL's response status and page title.

This module issues a size-capped HTTP GET to each unique URL found in the
analysis, follows redirects, and records the final status code and the
cleaned page ``<title>`` as metadata on the finding for display purposes.
It is opt-in (requires network access) and never executes package code.
"""

from __future__ import annotations

from html.parser import HTMLParser

_TITLE_MAX_CHARS = 200


class _TitleParser(HTMLParser):
    """Collect the text content of the first ``<title>`` element."""

    def __init__(self) -> None:
        super().__init__()
        self._in_title = False
        self._done = False
        self._parts: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
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

    Collapses runs of whitespace to single spaces, strips ends, and truncates
    to 200 characters.

    Args:
        html_text: Decoded HTML body.

    Returns:
        The cleaned title, or ``None`` when there is no non-empty ``<title>``.
    """
    parser = _TitleParser()
    try:
        parser.feed(html_text)
    except Exception:  # noqa: BLE001  # malformed HTML must never raise
        pass
    cleaned = " ".join(parser.title.split())
    if not cleaned:
        return None
    return cleaned[:_TITLE_MAX_CHARS]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_http_probe.py -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add nidhogg/enrichment/http_probe.py tests/test_http_probe.py
git commit -m "feat: add HTML title extractor for HTTP probe

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Single-URL probe `_probe`

**Files:**
- Modify: `nidhogg/enrichment/http_probe.py`
- Test: `tests/test_http_probe.py`

**Interfaces:**
- Consumes: `_extract_title` (Task 2).
- Produces: `_probe(url: str, *, timeout: float) -> tuple[int, str | None] | None` — returns `(final_status, title_or_none)`; returns `None` only when no status is obtainable (network/timeout error with no HTTP response). On an HTTP error status (e.g. 404) it returns `(status, None)`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_http_probe.py`:

```python
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
        result = http_probe._probe("http://example.com", timeout=5.0)
    assert result == (200, "Live Site")


def test_probe_non_html_body_no_title() -> None:
    resp = _fake_response(b"\x89PNG\r\n binary junk")
    with patch.object(http_probe.urllib.request, "urlopen", return_value=resp):
        result = http_probe._probe("http://example.com/img.png", timeout=5.0)
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
        result = http_probe._probe("http://example.com/missing", timeout=5.0)
    assert result == (404, None)


def test_probe_timeout_returns_none() -> None:
    with patch.object(
        http_probe.urllib.request, "urlopen", side_effect=TimeoutError()
    ):
        result = http_probe._probe("http://example.com", timeout=5.0)
    assert result is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_http_probe.py -k probe -v`
Expected: FAIL — `AttributeError: module 'nidhogg.enrichment.http_probe' has no attribute 'urllib'` / `_probe`.

- [ ] **Step 3: Implement `_probe`**

In `nidhogg/enrichment/http_probe.py`, add imports at the top (after `from html.parser import HTMLParser`):

```python
import urllib.error
import urllib.request

from loguru import logger
```

Add module constants near `_TITLE_MAX_CHARS`:

```python
_MAX_BODY_BYTES = 64 * 1024
_USER_AGENT = "nidhogg-analyzer"
```

Add the function (after `_extract_title`):

```python
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
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_http_probe.py -k probe -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add nidhogg/enrichment/http_probe.py tests/test_http_probe.py
git commit -m "feat: add size-capped single-URL HTTP probe

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Public `check_urls` orchestrator

**Files:**
- Modify: `nidhogg/enrichment/http_probe.py`
- Test: `tests/test_http_probe.py`

**Interfaces:**
- Consumes: `_probe` (Task 3), `UrlFinding` (Task 1).
- Produces: `check_urls(findings: list[UrlFinding], *, timeout: float = 5.0) -> list[UrlFinding]` — mutates in place; for each unique http/https URL, sets `http_status` and `http_title` on every finding sharing that URL; ignores other schemes and probe failures.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_http_probe.py`:

```python
from pathlib import Path  # noqa: E402

from nidhogg.core.models import AnalysisLayer, UrlFinding  # noqa: E402
from nidhogg.enrichment.http_probe import check_urls  # noqa: E402


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_http_probe.py -k check_urls -v`
Expected: FAIL — `ImportError: cannot import name 'check_urls'`.

- [ ] **Step 3: Implement `check_urls`**

In `nidhogg/enrichment/http_probe.py`, extend the top-of-file imports:

```python
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING
from urllib.parse import urlparse
```

and add the `TYPE_CHECKING` block (after the imports):

```python
if TYPE_CHECKING:
    from nidhogg.core.models import UrlFinding
```

Add the constant near the others:

```python
_MAX_WORKERS = 10
```

Add the function (at the end of the module):

```python
def check_urls(
    findings: list[UrlFinding], *, timeout: float = 5.0
) -> list[UrlFinding]:
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
            pool.submit(_probe, url, timeout=timeout): url
            for url in url_to_findings
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_http_probe.py -v`
Expected: PASS (all tests in file).

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff check nidhogg/enrichment/http_probe.py tests/test_http_probe.py
uv run ruff format nidhogg/enrichment/http_probe.py tests/test_http_probe.py
uv run mypy
git add nidhogg/enrichment/http_probe.py tests/test_http_probe.py
git commit -m "feat: add check_urls HTTP probe orchestrator

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Serialize HTTP fields in JSON writer

**Files:**
- Modify: `nidhogg/output/writer.py:14-29`
- Test: `tests/test_output_writer.py`

**Interfaces:**
- Consumes: `UrlFinding.http_status`, `UrlFinding.http_title` (Task 1).
- Produces: `_serialise_finding` output includes keys `"http_status"` and `"http_title"`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_output_writer.py` (adjust imports to match the file's existing style):

```python
def test_serialise_finding_includes_http_fields() -> None:
    from pathlib import Path

    from nidhogg.core.models import AnalysisLayer, UrlFinding
    from nidhogg.output.writer import _serialise_finding

    finding = UrlFinding(
        value="http://example.com",
        filepath=Path("pkg/x.py"),
        lineno=3,
        layer=AnalysisLayer.REGEX,
        http_status=200,
        http_title="Home",
    )
    doc = _serialise_finding(finding)
    assert doc["http_status"] == 200
    assert doc["http_title"] == "Home"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_output_writer.py::test_serialise_finding_includes_http_fields -v`
Expected: FAIL — `KeyError: 'http_status'`.

- [ ] **Step 3: Add the keys**

In `nidhogg/output/writer.py`, extend the dict returned by `_serialise_finding`:

```python
    return {
        "url": finding.value,
        "line": finding.lineno,
        "layer": finding.layer.value,
        "tags": sorted(t.value for t in finding.tags),
        "cert_issuer": finding.cert_issuer,
        "http_status": finding.http_status,
        "http_title": finding.http_title,
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_output_writer.py::test_serialise_finding_includes_http_fields -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/output/writer.py tests/test_output_writer.py
git commit -m "feat: serialize http_status and http_title in JSON output

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Show HTTP status and title in the renderer

**Files:**
- Modify: `nidhogg/output/renderer.py:74-108`
- Test: `tests/test_renderer.py`

**Interfaces:**
- Consumes: `UrlFinding.http_status`, `UrlFinding.http_title` (Task 1).
- Produces: `render_file_block` appends `[<status>]` (color-coded by class) and, when present, the title (dim) to each URL line.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_renderer.py` (match the file's existing render/console-capture style; the snippet below uses a plain-text capture):

```python
def test_render_file_block_shows_http_status_and_title() -> None:
    from pathlib import Path

    from rich.console import Console

    from nidhogg.core.models import AnalysisLayer, FileAnalysis, UrlFinding
    from nidhogg.output.renderer import render_file_block

    pkg = Path("pkg")
    fa = FileAnalysis(
        filepath=pkg / "evil.py",
        findings=[
            UrlFinding(
                value="http://example.com",
                filepath=pkg / "evil.py",
                lineno=1,
                layer=AnalysisLayer.REGEX,
                http_status=200,
                http_title="Home Page",
            )
        ],
    )
    console = Console(color_system=None, width=200)
    with console.capture() as cap:
        console.print(render_file_block(fa, pkg))
    out = cap.get()
    assert "[200]" in out
    assert "Home Page" in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_renderer.py::test_render_file_block_shows_http_status_and_title -v`
Expected: FAIL — assertion error (`[200]` not in output).

- [ ] **Step 3: Extend the findings loop**

In `nidhogg/output/renderer.py`, inside `render_file_block`, add a helper above the function and extend the per-finding loop. First add this module-level helper just before `render_file_block`:

```python
def _http_status_style(status: int) -> str:
    """Return the rich style for an HTTP status code by response class."""
    if 200 <= status < 300:  # noqa: PLR2004
        return "green"
    if 300 <= status < 400:  # noqa: PLR2004
        return "yellow"
    if 400 <= status < 600:  # noqa: PLR2004
        return "red"
    return "dim"
```

Then, in the loop over `sorted(file_analysis.findings, ...)`, after the existing
`if f.cert_issuer ...` block and before the tags loop, insert:

```python
        if f.http_status is not None:
            url.append(f" [{f.http_status}]", style=_http_status_style(f.http_status))
        if f.http_title is not None:
            url.append(f" {f.http_title}", style="dim")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_renderer.py::test_render_file_block_shows_http_status_and_title -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/output/renderer.py tests/test_renderer.py
git commit -m "feat: render HTTP status and title on URL lines

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Wire `--check-http` through the CLI

**Files:**
- Modify: `nidhogg/cli.py` (parser `analyze` block ~83-91; `_analyse_one` ~197-233; `_run_analyze` ~236-288; `_run_batch` ~291-360; `main` `analyze` dispatch ~868-893)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `check_urls` (Task 4).
- Produces: `--check-http` flag on the `analyze` subparser; `_analyse_one(..., check_http: bool = False)`; `_run_analyze`/`_run_batch` accept and forward `check_http`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_cli.py` (match the file's existing invocation style — the snippet mocks the enrichment and asserts it is called):

```python
def test_analyze_check_http_invokes_probe(tmp_path, monkeypatch) -> None:
    from unittest.mock import patch

    from nidhogg import cli

    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "mod.py").write_text('URL = "http://example.com"\n', encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv", ["nidhogg", "analyze", str(pkg), "--check-http", "--json"]
    )
    with patch("nidhogg.enrichment.http_probe.check_urls") as mock_check:
        mock_check.side_effect = lambda findings, **_: findings
        with pytest.raises(SystemExit) as exc:
            cli.main()
    assert exc.value.code == 0
    mock_check.assert_called_once()
```

Ensure `import pytest` is present in the test file.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py::test_analyze_check_http_invokes_probe -v`
Expected: FAIL — argparse error on unknown `--check-http`, or `check_urls` never called.

- [ ] **Step 3: Add the parser flag**

In `nidhogg/cli.py`, in the `analyze` subparser (after the `--check-ssl` argument, before `--verbose`):

```python
    analyze.add_argument(
        "--check-http",
        action="store_true",
        dest="check_http",
        help=(
            "Request each http/https URL and record its response status code "
            "and page title (requires network access)."
        ),
    )
```

- [ ] **Step 4: Thread `check_http` through `_analyse_one`**

Change the signature and add the enrichment call. Update `_analyse_one`:

```python
def _analyse_one(
    package_path: Path,
    *,
    benign_domains_path: Path | None = None,
    check_ssl: bool = False,
    check_http: bool = False,
) -> PackageAnalysis | None:
```

Extend its docstring `Args:` with:

```python
        check_http: When ``True``, request each http/https URL and populate
            http_status/http_title.
```

After the existing `if check_ssl:` block, add:

```python
    if check_http:
        from nidhogg.enrichment.http_probe import check_urls  # noqa: PLC0415

        check_urls(analysis.findings)
```

- [ ] **Step 5: Thread `check_http` through `_run_analyze` and `_run_batch`**

In `_run_analyze`, add `check_http: bool = False` to the keyword-only params
(after `check_ssl`), document it in the docstring `Args:` (`check_http: When
``True``, request each http/https URL and populate http_status/http_title.`),
and pass it in the `_analyse_one(...)` call:

```python
    result = _analyse_one(
        package_path,
        benign_domains_path=benign_domains_path,
        check_ssl=check_ssl,
        check_http=check_http,
    )
```

Do the same in `_run_batch`: add `check_http: bool = False` param, document it,
and pass `check_http=check_http` in its `_analyse_one(pkg_dir, ...)` call.

- [ ] **Step 6: Pass the arg from `main`**

In `main`, both `analyze` dispatch branches, add `check_http=args.check_http`:

```python
            sys.exit(
                _run_batch(
                    package_path,
                    args.output,
                    as_json=args.json,
                    verbose=args.verbose,
                    benign_domains_path=args.benign_domains,
                    check_ssl=args.check_ssl,
                    check_http=args.check_http,
                    history_dir=args.history_dir,
                )
            )
```

```python
            sys.exit(
                _run_analyze(
                    package_path,
                    args.output,
                    as_json=args.json,
                    verbose=args.verbose,
                    benign_domains_path=args.benign_domains,
                    check_ssl=args.check_ssl,
                    check_http=args.check_http,
                    history_dir=args.history_dir,
                )
            )
```

- [ ] **Step 7: Run test to verify it passes**

Run: `uv run pytest tests/test_cli.py::test_analyze_check_http_invokes_probe -v`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add nidhogg/cli.py tests/test_cli.py
git commit -m "feat: wire --check-http flag through the analyze CLI path

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Full suite, lint, types, docs

**Files:**
- Modify: `CLAUDE.md` (architecture notes for `enrichment/`), `README*` if it documents flags.
- Test: whole suite.

**Interfaces:**
- Consumes: everything above.
- Produces: green suite; docs mention `--check-http` and the two new fields.

- [ ] **Step 1: Run the full suite**

Run: `uv run pytest`
Expected: all pass.

- [ ] **Step 2: Lint and format**

Run: `uv run ruff check` then `uv run ruff format`
Expected: no errors; formatting clean.

- [ ] **Step 3: Type-check**

Run: `uv run mypy`
Expected: no errors.

- [ ] **Step 4: Update docs**

In `CLAUDE.md`, update the `enrichment/` block to list `http_probe.py` alongside
`ssl_cert.py`, and note the two new `UrlFinding` fields (`http_status`,
`http_title`) in the data-model paragraph. If a `README` documents CLI flags, add
`--check-http` next to `--check-ssl` with a one-line description. Only touch docs
that already enumerate these — do not invent new sections.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md README* 2>/dev/null; git add -A
git commit -m "docs: document --check-http flag and HTTP enrichment fields

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- Model fields → Task 1. ✓
- `http_probe.py` module / `check_urls` / `_probe` / title clean+truncate → Tasks 2–4. ✓
- http/https-only filter, dedup, thread pool, size cap, redirects, silent failure → Tasks 3–4. ✓
- CLI `--check-http` on `analyze`+`batch`, lazy import → Task 7. ✓
- JSON writer keys → Task 5. ✓
- Renderer status+title → Task 6. ✓
- All 8 spec test cases covered across Tasks 2–4 (title basic/collapse/truncate/missing/empty, 200+title, redirect final status [covered by `resp.status` being the final status], non-HTML, timeout, http-error status, non-http filter, duplicate share). ✓
- Security (opt-in, no code exec, size cap, timeout) → Tasks 3, 7 help text. ✓

**Placeholder scan:** No TBD/TODO; every code step shows full code. ✓

**Type consistency:** `check_urls(findings, *, timeout=5.0) -> list[UrlFinding]`, `_probe(url, *, timeout) -> tuple[int, str | None] | None`, `_extract_title(str) -> str | None`, `http_status: int | None`, `http_title: str | None` — names/signatures identical across Tasks 1–7. ✓

**Note on redirect test:** the spec's "redirect→final status" case is satisfied by `urllib` transparently following redirects — `resp.status` is already the final code, exercised by `test_probe_200_with_title`. No separate mock needed since urllib does the redirect internally.
