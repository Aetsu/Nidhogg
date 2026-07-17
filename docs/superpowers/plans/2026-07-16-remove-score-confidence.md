# Remove Score and Confidence - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove score and confidence concepts from the codebase, leaving only qualitative URL detection data (method, domain_threat, cert_issuer).

**Architecture:** Eliminate the classifier and scoring modules entirely. Update all consumers (analysis layers, aggregator, enrichment, output, CLI, web) to work without confidence/score fields. The pipeline becomes: walker → [layer1, layer2] → aggregator → enrichment → output.

**Tech Stack:** Python 3.14, pytest, rich (for CLI output), vanilla JS (for web)

## Global Constraints

- Python 3.14 — use recent features where they add clarity
- uv — dependency management. Never use pip directly
- pytest — testing
- loguru — structured logging
- ruff — linting and formatting (configured in pyproject.toml)
- mypy — strict type checking
- No comments unless explaining non-obvious logic

---

### Task 1: Update Core Models

**Files:**
- Modify: `nidhogg/core/models.py:43-86`

**Interfaces:**
- Consumes: Nothing (foundation change)
- Produces: Updated `UrlFinding` (no confidence) and `PackageAnalysis` (no score)

- [ ] **Step 1: Remove confidence from UrlFinding**

Edit `nidhogg/core/models.py`, remove the `confidence` field from `UrlFinding`:

```python
@dataclass
class UrlFinding:
    """A single URL candidate found during package analysis.

    Attributes:
        value: The extracted URL string.
        filepath: Path to the source file where the URL was found.
        lineno: Line number in the source file (1-indexed).
        layer: Which analysis layer produced this finding.
        method: Which detection technique resolved the URL.
        cert_issuer: TLS certificate issuer organisation, set by the SSL
            enrichment step.  ``None`` when the check was not performed or
            the domain does not serve HTTPS.
        domain_threat: Threat category assigned to the URL's host, if any.
    """

    value: str
    filepath: Path
    lineno: int
    layer: AnalysisLayer
    method: DetectionMethod
    cert_issuer: str | None = None
    domain_threat: DomainThreatCategory | None = None
```

- [ ] **Step 2: Remove score from PackageAnalysis**

Edit `nidhogg/core/models.py`, remove the `score` field from `PackageAnalysis`:

```python
@dataclass
class PackageAnalysis:
    """Aggregated results of analysing a single package directory.

    Attributes:
        name: Package name (derived from the directory name).
        path: Absolute path to the package directory.
        findings: All URL findings collected across every source file.
    """

    name: str
    path: Path
    findings: list[UrlFinding] = field(default_factory=list)
```

- [ ] **Step 3: Run tests to see failures**

Run: `uv run pytest tests/test_models.py -v`
Expected: Tests will fail because they reference removed fields

- [ ] **Step 4: Update test_models.py**

Edit `tests/test_models.py` to remove any tests that reference `confidence` or `score`. If the file only tests those fields, delete it entirely.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/core/models.py tests/test_models.py
git commit -m "refactor: remove confidence and score from core models"
```

---

### Task 2: Update Layer 1 (Regex)

**Files:**
- Modify: `nidhogg/analysis/layer1_regex.py:122-223`

**Interfaces:**
- Consumes: Updated `UrlFinding` (no confidence field)
- Produces: `extract_urls_regex()` returns findings without confidence

- [ ] **Step 1: Remove confidence from URL findings**

Edit `nidhogg/analysis/layer1_regex.py`, in `extract_urls_regex()`, remove `confidence=0.45`:

```python
for lineno, line in enumerate(source.splitlines(), start=1):
    for match in _URL_RE.finditer(line):
        url = _clean_url(match.group())
        findings.append(
            UrlFinding(
                value=url,
                filepath=filepath,
                lineno=lineno,
                layer=AnalysisLayer.REGEX,
                method=DetectionMethod.LITERAL,
            )
        )
```

- [ ] **Step 2: Remove confidence from IP findings**

Edit `nidhogg/analysis/layer1_regex.py`, in `_extract_ips()`, remove `confidence=0.80` from both IPv4 and IPv6 findings:

```python
findings.append(
    UrlFinding(
        value=raw_ip,
        filepath=filepath,
        lineno=lineno,
        layer=AnalysisLayer.REGEX,
        method=DetectionMethod.IP,
    )
)
```

Update the docstring to remove the confidence mention:

```python
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
        A list of :class:`UrlFinding` objects with
        ``method=DetectionMethod.IP``.
    """
```

- [ ] **Step 3: Run layer1 tests**

Run: `uv run pytest tests/test_layer1_regex.py -v`
Expected: Tests that check confidence values will fail

- [ ] **Step 4: Update test_layer1_regex.py**

Remove or update tests that check confidence:
- Remove `test_finding_confidence_below_one`
- Remove `test_ip_finding_confidence_is_080`

- [ ] **Step 5: Commit**

```bash
git add nidhogg/analysis/layer1_regex.py tests/test_layer1_regex.py
git commit -m "refactor: remove confidence from layer1 regex analysis"
```

---

### Task 3: Update Layer 2 (AST)

**Files:**
- Modify: `nidhogg/analysis/layer2_ast.py:172-284`

**Interfaces:**
- Consumes: Updated `UrlFinding` (no confidence field)
- Produces: `extract_urls_ast()` returns findings without confidence

- [ ] **Step 1: Remove confidence parameter from _emit()**

Edit `nidhogg/analysis/layer2_ast.py`, update `_emit()` method in `_UrlVisitor`:

```python
def _emit(
    self, url: str, lineno: int, method: DetectionMethod
) -> None:
    self.findings.append(
        UrlFinding(
            value=url,
            filepath=self._filepath,
            lineno=lineno,
            layer=AnalysisLayer.AST,
            method=method,
        )
    )
```

- [ ] **Step 2: Update all _emit() calls**

Remove the confidence argument from all `_emit()` calls:

```python
def visit_Constant(self, node: ast.Constant) -> None:
    """Detect string constants that contain a URL."""
    if isinstance(node.value, str):
        for url in _urls_in(node.value):
            self._emit(url, node.lineno, DetectionMethod.LITERAL)
    self.generic_visit(node)

def visit_BinOp(self, node: ast.BinOp) -> None:
    """Fold string operands into a single value and check for URLs.

    Priority: pure Constant folding (CONCAT) → scope-assisted resolution
    (SCOPE_TRACKING) → descend into children.
    """
    folded = _fold_binop(node)
    if folded is not None:
        for url in _urls_in(folded):
            self._emit(url, node.lineno, DetectionMethod.CONCAT)
        return
    resolved = _resolve_to_str(node, self._scope, node.lineno)
    if resolved is not None:
        for url in _urls_in(resolved):
            self._emit(url, node.lineno, DetectionMethod.SCOPE_TRACKING)
        return
    self.generic_visit(node)

def visit_Call(self, node: ast.Call) -> None:
    """Detect base64.b64decode() with a Constant arg."""
    func = node.func

    is_b64 = (isinstance(func, ast.Name) and func.id == "b64decode") or (
        isinstance(func, ast.Attribute) and func.attr == "b64decode"
    )
    if is_b64 and node.args:
        arg = node.args[0]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str | bytes):
            decoded = _try_b64decode(arg.value)
            if decoded:
                for url in _urls_in(decoded):
                    self._emit(url, node.lineno, DetectionMethod.BASE64)

    self.generic_visit(node)

def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
    """Resolve f-strings, falling back to scope tracking for Name interpolations."""
    resolved = _resolve_fstring(node)
    if resolved is not None:
        for url in _urls_in(resolved):
            self._emit(url, node.lineno, DetectionMethod.FSTRING)
        return
    resolved_scope = _resolve_fstring_scope(node, self._scope)
    if resolved_scope is not None:
        for url in _urls_in(resolved_scope):
            self._emit(url, node.lineno, DetectionMethod.SCOPE_TRACKING)
        return
    self.generic_visit(node)
```

- [ ] **Step 3: Run layer2 tests**

Run: `uv run pytest tests/test_layer2_ast.py -v`
Expected: Tests that check confidence will fail

- [ ] **Step 4: Update test_layer2_ast.py**

Remove `test_confidence_higher_than_regex_layer` entirely.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/analysis/layer2_ast.py tests/test_layer2_ast.py
git commit -m "refactor: remove confidence from layer2 AST analysis"
```

---

### Task 4: Update Aggregator

**Files:**
- Modify: `nidhogg/analysis/aggregator.py:212-264`

**Interfaces:**
- Consumes: Updated `UrlFinding` (no confidence field)
- Produces: `aggregate()` returns deduplicated findings with domain_threat but no confidence modifications

- [ ] **Step 1: Simplify deduplication logic**

Edit `nidhogg/analysis/aggregator.py`, in `aggregate()`, remove confidence comparison:

```python
def aggregate(
    findings: list[UrlFinding],
    *,
    benign_domains: frozenset[str] = _BENIGN_DOMAINS,
) -> list[UrlFinding]:
    """Deduplicate and normalise a list of URL findings.

    For duplicate URLs (same normalised value) the first finding is kept.
    Normalisation lowercases the domain, strips URL fragments (``#…``),
    and removes trailing slashes from the path.
    URLs whose host belongs to *benign_domains* are discarded entirely.
    URLs with invalid characters are cleaned, and those that remain invalid
    after cleaning are filtered out.

    Args:
        findings: Raw findings from one or more analysis layers.
        benign_domains: Set of domain names to treat as benign and filter out.
            Defaults to ``_BENIGN_DOMAINS``.

    Returns:
        A deduplicated, normalised, and filtered list of findings, in the
        order the winning finding for each URL was first encountered.
    """
    seen: dict[str, UrlFinding] = {}
    for finding in findings:
        cleaned_url = _clean_url(finding.value)
        if not _is_valid_url(cleaned_url):
            continue
        normalized_url = _normalize(cleaned_url)
        if _is_benign(normalized_url, benign_domains):
            continue
        if _is_non_public_ip(normalized_url):
            continue
        if normalized_url not in seen:
            seen[normalized_url] = dataclasses.replace(finding, value=normalized_url)

    result: list[UrlFinding] = []
    for raw in seen.values():
        threat = classify_domain(raw.value)
        if threat is not None:
            result.append(
                dataclasses.replace(raw, domain_threat=threat)
            )
        else:
            result.append(raw)
    return result
```

- [ ] **Step 2: Remove unused imports**

Remove the import of `load_scoring_config` and `_HIGH_SEVERITY_THREATS`:

```python
from nidhogg.analysis.domain_classifier import classify_domain
from nidhogg.core.models import DomainThreatCategory
```

Remove:
```python
_HIGH_SEVERITY_THREATS = frozenset(
    [DomainThreatCategory.EXFILTRATION, DomainThreatCategory.MALWARE_HOSTING]
)
```

- [ ] **Step 3: Run aggregator tests**

Run: `uv run pytest tests/test_aggregator.py -v`
Expected: Tests checking confidence boosts will fail

- [ ] **Step 4: Update test_aggregator.py**

Remove tests related to confidence:
- `test_aggregate_keeps_highest_confidence`
- `test_aggregate_keeps_highest_confidence_regardless_of_order`
- `test_aggregate_boosts_confidence_normal_category`
- `test_aggregate_boosts_confidence_high_severity_exfiltration`
- `test_aggregate_boosts_confidence_high_severity_malware_hosting`
- `test_aggregate_confidence_boost_capped_at_099`
- `test_aggregate_domain_threat_none_leaves_confidence_unchanged`

Update remaining tests to remove `confidence` parameter from `_finding()` calls.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/analysis/aggregator.py tests/test_aggregator.py
git commit -m "refactor: remove confidence boosts from aggregator"
```

---

### Task 5: Update SSL Certificate Enrichment

**Files:**
- Modify: `nidhogg/enrichment/ssl_cert.py:1-122`

**Interfaces:**
- Consumes: Updated `UrlFinding` (no confidence field)
- Produces: `check_certificates()` sets only `cert_issuer`, no confidence modification

- [ ] **Step 1: Remove confidence modification logic**

Edit `nidhogg/enrichment/ssl_cert.py`, simplify `check_certificates()`:

```python
def check_certificates(
    findings: list[UrlFinding], *, timeout: float = 3.0
) -> list[UrlFinding]:
    """Check TLS certificates for each unique HTTPS domain in *findings*.

    Connects to port 443 of each unique domain and reads the certificate
    issuer. Non-HTTPS URLs and connection failures are silently skipped
    so the pipeline never blocks on network issues.

    Args:
        findings: Deduplicated URL findings from the aggregator.
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
            hostname = future.result()
            issuer = future_to_host[future]
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
```

Wait, I made an error. Let me fix:

```python
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
```

- [ ] **Step 2: Remove unused imports**

Remove the import of `load_scoring_config`:

```python
from loguru import logger
```

Remove:
```python
from nidhogg.scoring import load_scoring_config
```

- [ ] **Step 3: Update module docstring**

Update the module docstring to remove confidence mention:

```python
"""SSL certificate enrichment: read TLS certificate issuer for HTTPS domains.

This module connects to each unique HTTPS domain found in the analysis
and reads the TLS certificate issuer organisation. The issuer is stored
as metadata on the finding for display purposes.
"""
```

- [ ] **Step 4: Run SSL tests**

Run: `uv run pytest tests/test_ssl_cert.py -v`
Expected: Tests checking confidence bump will fail

- [ ] **Step 5: Update test_ssl_cert.py**

Remove or update tests that check confidence modification. Keep tests that verify `cert_issuer` is set correctly.

- [ ] **Step 6: Commit**

```bash
git add nidhogg/enrichment/ssl_cert.py tests/test_ssl_cert.py
git commit -m "refactor: remove confidence bump from SSL enrichment"
```

---

### Task 6: Delete Scoring Module

**Files:**
- Delete: `nidhogg/scoring.py`
- Delete: `nidhogg/data/scoring.toml`
- Delete: `tests/test_scoring.py`

**Interfaces:**
- Consumes: Nothing
- Produces: Removal of scoring infrastructure

- [ ] **Step 1: Delete scoring.py**

```bash
rm nidhogg/scoring.py
```

- [ ] **Step 2: Delete scoring.toml**

```bash
rm nidhogg/data/scoring.toml
```

- [ ] **Step 3: Delete test_scoring.py**

```bash
rm tests/test_scoring.py
```

- [ ] **Step 4: Verify no imports remain**

Run: `grep -r "from nidhogg.scoring" nidhogg/ tests/`
Expected: No output (all imports already removed)

Run: `grep -r "import scoring" nidhogg/ tests/`
Expected: No output

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: delete scoring module and configuration"
```

---

### Task 7: Delete Classifier Module

**Files:**
- Delete: `nidhogg/classifier.py`
- Delete: `tests/test_classifier.py`

**Interfaces:**
- Consumes: Nothing
- Produces: Removal of classifier infrastructure

- [ ] **Step 1: Delete classifier.py**

```bash
rm nidhogg/classifier.py
```

- [ ] **Step 2: Delete test_classifier.py**

```bash
rm tests/test_classifier.py
```

- [ ] **Step 3: Verify no imports remain**

Run: `grep -r "from nidhogg.classifier" nidhogg/ tests/`
Expected: No output

Run: `grep -r "import classifier" nidhogg/ tests/`
Expected: No output

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: delete classifier module"
```

---

### Task 8: Update Renderer

**Files:**
- Modify: `nidhogg/output/renderer.py:1-339`

**Interfaces:**
- Consumes: Updated `PackageAnalysis` (no score field)
- Produces: Rendering functions that work without score/confidence

- [ ] **Step 1: Remove render_score_bar()**

Delete the entire `render_score_bar()` function (lines 78-91).

- [ ] **Step 2: Update render_findings_table()**

Remove the "Conf" column and confidence styling:

```python
def render_findings_table(findings: list[UrlFinding], pkg_path: Path) -> Table:
    """Render URL findings as a borderless rich table.

    Columns: LOC, Method, URL. Rows are sorted by method then URL.
    Inline ``[LE]`` (Let's Encrypt issuer) and ``[<THREAT>]`` tags are appended
    to the URL cell.

    Args:
        findings: Findings to render.
        pkg_path: Package root used to relativise file paths.

    Returns:
        A borderless ``rich.table.Table``.
    """
    table = Table(box=None, show_header=False, pad_edge=False, expand=False)
    table.add_column("LOC", no_wrap=True)
    table.add_column("Method", no_wrap=True)
    table.add_column("URL")

    for f in sorted(findings, key=lambda x: (x.method.value, x.value)):
        try:
            rel = str(f.filepath.relative_to(pkg_path))
        except ValueError:
            rel = str(f.filepath)
        loc = Text(f"{rel}:{f.lineno}")
        method = Text(f.method.value, style="dim")
        url = Text(f.value)
        if f.cert_issuer is not None and "Let's Encrypt" in f.cert_issuer:
            url.append(" [LE]", style="yellow")
        if f.domain_threat is not None:
            url.append(
                f" [{f.domain_threat.value.upper()}]",
                style="bold red",
            )
        table.add_row(loc, method, url)
    return table
```

- [ ] **Step 3: Update render_package_header()**

Remove the `score` parameter:

```python
def render_package_header(name: str) -> Text:
    """Render the per-package header used in batch and monitor output.

    Args:
        name: Package display name.

    Returns:
        A ``Text`` like ``"── evilpkg"``.
    """
    line = Text()
    line.append(f"── {name}", style="bold")
    return line
```

- [ ] **Step 4: Update render_package_result()**

Remove score display:

```python
def render_package_result(
    analysis: PackageAnalysis,
    *,
    display_name: str | None = None,
) -> Group | Text:
    """Render the full human-readable block for one package.

    When there are no findings, delegates to :func:`render_empty`. Otherwise
    returns a ``Group`` of the header lines and findings table.

    Args:
        analysis: Completed package analysis.
        display_name: Override the package name in the header.

    Returns:
        A ``Group`` of renderables, or a ``Text`` for the empty case.
    """
    if not analysis.findings:
        return render_empty(analysis, display_name=display_name)

    name = display_name or analysis.name

    lines: list[Text] = [
        Text("package  ").append(name, style="bold"),
        Text("path     ").append(str(analysis.path), style="dim"),
        Text(""),
        Text(f"findings {len(analysis.findings)}"),
        Text(""),
        Text("URLs:", style="bold"),
    ]
    return Group(*lines, render_findings_table(analysis.findings, analysis.path))
```

- [ ] **Step 5: Remove render_batch_summary() and related code**

Delete `render_batch_summary()`, `_RISK_MALICIOUS`, `_RISK_CLEAN`, and `_BATCH_SCORE_THRESHOLD` (lines 207-272).

- [ ] **Step 6: Run renderer tests**

Run: `uv run pytest tests/test_renderer.py -v`
Expected: Many tests will fail

- [ ] **Step 7: Update test_renderer.py**

Remove tests for:
- `render_score_bar`
- Confidence styling in findings table
- Batch summary
- Risk level display

Update remaining tests to work without score/confidence.

- [ ] **Step 8: Commit**

```bash
git add nidhogg/output/renderer.py tests/test_renderer.py
git commit -m "refactor: remove score and confidence from renderer"
```

---

### Task 9: Update Writer

**Files:**
- Modify: `nidhogg/output/writer.py:1-104`

**Interfaces:**
- Consumes: Updated `PackageAnalysis` (no score field)
- Produces: JSON output without score, confidence, or risk_level

- [ ] **Step 1: Remove _risk_level()**

Delete the `_risk_level()` function entirely (lines 20-31).

- [ ] **Step 2: Update _serialise_finding()**

Remove `confidence` from the output:

```python
def _serialise_finding(finding: UrlFinding, package_path: Path) -> dict[str, object]:
    """Convert a single finding to a JSON-serialisable dict.

    File paths are expressed relative to *package_path* for portability.

    Args:
        finding: The finding to serialise.
        package_path: Root of the analysed package (used to relativise paths).

    Returns:
        A plain dict suitable for ``json.dumps``.
    """
    try:
        rel = finding.filepath.relative_to(package_path)
    except ValueError:
        rel = finding.filepath
    return {
        "url": finding.value,
        "file": str(rel),
        "line": finding.lineno,
        "layer": finding.layer.value,
        "method": finding.method.value,
        "cert_issuer": finding.cert_issuer,
        "domain_threat": finding.domain_threat.value if finding.domain_threat else None,
    }
```

- [ ] **Step 3: Update build_document()**

Remove `score` and `risk_level` from summary:

```python
def build_document(analysis: PackageAnalysis) -> dict[str, object]:
    """Build the JSON-serialisable result document for *analysis*.

    Args:
        analysis: Completed package analysis.

    Returns:
        A plain dict containing ``package``, ``summary``, and ``findings``
        sections, ready for ``json.dumps``.
    """
    return {
        "package": {
            "name": analysis.name,
            "path": str(analysis.path),
        },
        "summary": {
            "total_findings": len(analysis.findings),
        },
        "findings": [_serialise_finding(f, analysis.path) for f in analysis.findings],
    }
```

- [ ] **Step 4: Update write_results() docstring**

Update the docstring to remove risk level mention:

```python
def write_results(analysis: PackageAnalysis, destination: Path) -> None:
    """Write analysis results to *destination* as a JSON file.

    The document contains:

    * **package** — name and path of the analysed package.
    * **summary** — finding count.
    * **findings** — each URL with its file, line, detection layer, method,
      and metadata.

    Args:
        analysis: Completed package analysis.
        destination: Path where the JSON file will be written.  The parent
            directory must already exist.
    """
    destination.write_text(
        json.dumps(build_document(analysis), indent=2), encoding="utf-8"
    )
```

- [ ] **Step 5: Run writer tests**

Run: `uv run pytest tests/test_output_writer.py -v`
Expected: Tests checking score, confidence, risk_level will fail

- [ ] **Step 6: Update test_output_writer.py**

Remove tests for:
- `test_risk_level_malicious_when_high_confidence_finding`
- `test_risk_level_clean_when_low_confidence`
- `test_findings_confidence_present`

Update remaining tests to remove confidence from fixtures.

- [ ] **Step 7: Commit**

```bash
git add nidhogg/output/writer.py tests/test_output_writer.py
git commit -m "refactor: remove score, confidence, and risk_level from writer"
```

---

### Task 10: Update CLI

**Files:**
- Modify: `nidhogg/cli.py:1-939`

**Interfaces:**
- Consumes: Updated modules without score/confidence/classifier
- Produces: CLI that works without classification

- [ ] **Step 1: Remove Verdict import and usage**

Remove the import:
```python
from nidhogg.classifier import Verdict, classify
```

Update `_analyse_one()` to not call classify:

```python
def _analyse_one(
    package_path: Path,
    *,
    benign_domains_path: Path | None = None,
    check_ssl: bool = False,
) -> PackageAnalysis | None:
    """Run the URL-analysis pipeline for a single package directory.

    Args:
        package_path: Directory of the package to analyse.
        benign_domains_path: Optional path to a custom benign domain list.
        check_ssl: When ``True``, query TLS certificates for each HTTPS domain
            and populate cert_issuer for Let's Encrypt issuers.

    Returns:
        A ``PackageAnalysis``, or ``None`` on read error.
    """
    try:
        analysis = analyze_package(package_path)
    except PackageReadError as exc:
        print(f"Error: {exc}", file=sys.stderr)  # noqa: T201
        return None

    if benign_domains_path is not None:
        analysis.findings = aggregate(
            analysis.findings,
            benign_domains=load_benign_domains(benign_domains_path),
        )
    else:
        analysis.findings = aggregate(analysis.findings)

    if check_ssl:
        from nidhogg.enrichment.ssl_cert import check_certificates  # noqa: PLC0415

        analysis.findings = check_certificates(analysis.findings)

    return analysis
```

- [ ] **Step 2: Update _run_analyze()**

Remove verdict handling and simplify exit codes:

```python
def _run_analyze(  # noqa: PLR0913
    package_path: Path,
    output: Path | None,
    *,
    as_json: bool,
    verbose: bool,
    benign_domains_path: Path | None = None,
    check_ssl: bool = False,
    history_dir: Path | None = None,
) -> int:
    """Run the full analysis pipeline for a single package and return an exit code.

    Args:
        package_path: Directory of the package to analyse.
        output: Write JSON to this path; ``None`` prints to stdout.
        as_json: Print JSON to stdout instead of the human-readable format.
        verbose: Keep loguru logging enabled when True.
        benign_domains_path: Optional path to a custom benign domain list.
        check_ssl: When ``True``, query TLS certificates for each HTTPS domain
            and populate cert_issuer.
        history_dir: When provided, append the result document as JSONL under
            this directory.

    Returns:
        ``0`` on success, ``2`` on error.
    """
    if not verbose:
        logger.remove()

    result = _analyse_one(
        package_path,
        benign_domains_path=benign_domains_path,
        check_ssl=check_ssl,
    )
    if result is None:
        return _EXIT_ERROR

    analysis = result

    if history_dir is not None:
        from nidhogg.output.history import append_finding  # noqa: PLC0415

        append_finding(history_dir, build_document(analysis))

    if output is not None:
        write_results(analysis, output)
    elif as_json:
        print(json.dumps(build_document(analysis), indent=2))  # noqa: T201
    else:
        console = make_console()
        console.print(render_package_result(analysis))

    return 0
```

- [ ] **Step 3: Update _run_batch()**

Remove verdict and batch_results handling:

```python
def _run_batch(  # noqa: C901, PLR0913
    packages_dir: Path,
    output: Path | None,
    *,
    as_json: bool,
    verbose: bool,
    benign_domains_path: Path | None = None,
    check_ssl: bool = False,
    history_dir: Path | None = None,
) -> int:
    """Run the analysis pipeline over every subdirectory of *packages_dir*.

    Args:
        packages_dir: Directory whose immediate subdirectories are packages.
        output: Write a JSON array with all results to this path.
        as_json: Print a JSON array to stdout instead of the human-readable format.
        verbose: Keep loguru logging enabled when True.
        benign_domains_path: Optional path to a custom benign domain list.
        check_ssl: When ``True``, query TLS certificates for each HTTPS domain
            and populate cert_issuer.
        history_dir: When provided, append each package's result document as
            JSONL under this directory.

    Returns:
        ``0`` on success, ``2`` if any package could not be read.
    """
    if not verbose:
        logger.remove()

    console = make_console()

    subdirs = sorted(p for p in packages_dir.iterdir() if p.is_dir())
    if not subdirs:
        print(f"No package directories found in {packages_dir}", file=sys.stderr)  # noqa: T201
        return _EXIT_ERROR

    exit_code = 0
    documents: list[dict[str, object]] = []

    for pkg_dir in subdirs:
        result = _analyse_one(
            pkg_dir,
            benign_domains_path=benign_domains_path,
            check_ssl=check_ssl,
        )
        if result is None:
            exit_code = _EXIT_ERROR
            continue

        analysis = result

        if history_dir is not None:
            from nidhogg.output.history import append_finding  # noqa: PLC0415

            append_finding(history_dir, build_document(analysis))

        if output is not None or as_json:
            documents.append(build_document(analysis))
        else:
            if analysis.findings:
                console.print()
                console.print(render_package_header(pkg_dir.name))
            console.print(render_package_result(analysis, display_name=pkg_dir.name))

    if output is not None:
        output.write_text(json.dumps(documents, indent=2), encoding="utf-8")
    elif as_json:
        print(json.dumps(documents, indent=2))  # noqa: T201

    return exit_code
```

- [ ] **Step 4: Update _run_fetch()**

Remove verdict handling:

```python
def _run_fetch(  # noqa: PLR0913
    name: str,
    version: str | None,
    output: Path | None,
    *,
    as_json: bool,
    verbose: bool,
    keep_download: str | None,
    history_dir: Path | None,
) -> int:
    """Download *name* from PyPI, analyse it, and return an exit code.

    Args:
        name: PyPI package name to download.
        version: Specific version to download, or ``None`` for the latest.
        output: Write JSON to this path; ``None`` prints to stdout.
        as_json: Print JSON to stdout instead of the human-readable format.
        verbose: Keep loguru logging enabled when True.
        keep_download: ``None`` to delete after analysis; ``""`` to keep in
            place; a non-empty string is a directory to move the extracted
            package into.
        history_dir: When provided, append the result document as JSONL
            under this directory.

    Returns:
        ``0`` on success, ``2`` on error.
    """
    if not verbose:
        logger.remove()

    from nidhogg.fetching.pypi_fetch import fetched_package  # noqa: PLC0415

    keep = keep_download is not None
    keep_dir = Path(keep_download) if keep_download else None

    try:
        with fetched_package(name, version, keep=keep, keep_dir=keep_dir) as path:
            result = _analyse_one(path)
    except PackageReadError as exc:
        print(f"Error: {exc}", file=sys.stderr)  # noqa: T201
        return _EXIT_ERROR

    if result is None:
        return _EXIT_ERROR

    analysis = result

    if history_dir is not None:
        from nidhogg.output.history import append_finding  # noqa: PLC0415

        append_finding(history_dir, build_document(analysis))

    if output is not None:
        write_results(analysis, output)
    elif as_json:
        print(json.dumps(build_document(analysis), indent=2))  # noqa: T201
    else:
        console = make_console()
        console.print(render_package_result(analysis))

    return 0
```

- [ ] **Step 5: Update _analyse_new_package()**

Remove Verdict from return type:

```python
def _analyse_new_package(
    name: str,
    *,
    keep_download: Path | None,
) -> PackageAnalysis | None:
    """Download, analyse, and clean up a single monitor-discovered package.

    Args:
        name: PyPI package name to download and analyse.
        keep_download: When provided, keep the extracted package under a
            per-package subdirectory of this directory.

    Returns:
        A ``PackageAnalysis``, or ``None`` on read error.
    """
    from nidhogg.fetching.pypi_fetch import fetched_package  # noqa: PLC0415

    keep = keep_download is not None
    keep_dir = keep_download / name if keep_download is not None else None
    with fetched_package(name, keep=keep, keep_dir=keep_dir) as path:
        return _analyse_one(path)
```

- [ ] **Step 6: Update _process_entries_plain()**

Remove verdict handling:

```python
def _process_entries_plain(
    entries: list[ChangelogEntry],
    *,
    keep_download: Path | None,
    concurrency: int,
    history_dir: Path | None,
    as_json: bool,
) -> None:
    """Analyse *entries* concurrently and print each result as it completes.

    This is the non-interactive code path used whenever stdout is not a
    terminal (redirected output, logs, CI) — no rich rendering involved.

    Args:
        entries: Changelog entries to analyse.
        keep_download: Forwarded to :func:`_analyse_new_package`.
        concurrency: Maximum concurrent downloads/analyses.
        history_dir: When provided, append each result to JSONL history.
        as_json: Print each result as JSON instead of the human-readable format.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed  # noqa: PLC0415

    console = make_console()

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {
            pool.submit(
                _analyse_new_package, entry.name, keep_download=keep_download
            ): entry
            for entry in entries
        }
        for future in as_completed(futures):
            entry = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to analyse {}: {}", entry.name, exc)
                continue
            if result is None:
                continue
            analysis = result
            if history_dir is not None:
                from nidhogg.output.history import append_finding  # noqa: PLC0415

                append_finding(history_dir, build_document(analysis))
            if as_json:
                print(json.dumps(build_document(analysis), indent=2))  # noqa: T201
            else:
                if analysis.findings:
                    console.print()
                    console.print(render_package_header(entry.name))
                console.print(render_package_result(analysis, display_name=entry.name))
```

- [ ] **Step 7: Update _analyse_with_progress()**

Remove Verdict from return type:

```python
def _analyse_with_progress(
    entry: ChangelogEntry,
    progress: Progress,
    keep_download: Path | None,
) -> PackageAnalysis | None:
    """Analyse *entry*, showing a spinner row only while this call is active.

    The spinner task is added when the call actually starts (i.e. once a
    worker thread picks it up) and removed when it finishes, so the live
    display only ever shows up to ``concurrency`` rows — the packages
    genuinely being analysed right now, not the whole queue.

    Args:
        entry: Changelog entry to analyse.
        progress: Shared progress display to add/remove this row on.
        keep_download: Forwarded to :func:`_analyse_new_package`.

    Returns:
        A ``PackageAnalysis``, or ``None`` on read error.
    """
    task_id = progress.add_task(f"  {entry.name}", total=None)
    try:
        return _analyse_new_package(entry.name, keep_download=keep_download)
    finally:
        progress.remove_task(task_id)
```

- [ ] **Step 8: Update _process_entries_rich()**

Remove verdict handling:

```python
def _process_entries_rich(  # noqa: PLR0913
    entries: list[ChangelogEntry],
    *,
    keep_download: Path | None,
    concurrency: int,
    history_dir: Path | None,
    as_json: bool,
    console: Console,
) -> None:
    """Analyse *entries* concurrently with a live rich progress display.

    Shows an overall "completed/total" bar plus one spinner row per package
    currently being analysed. Each result is printed through the progress's
    own console so the live display isn't corrupted.

    Args:
        entries: Changelog entries to analyse.
        keep_download: Forwarded to :func:`_analyse_new_package`.
        concurrency: Maximum concurrent downloads/analyses.
        history_dir: When provided, append each result to JSONL history.
        as_json: Print each result as JSON instead of the human-readable format.
        console: Rich console shared with the rest of the monitor loop.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed  # noqa: PLC0415

    with render_progress(console=console) as progress:
        overall_task = progress.add_task("Analizando paquetes", total=len(entries))

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {
                pool.submit(
                    _analyse_with_progress, entry, progress, keep_download
                ): entry
                for entry in entries
            }
            for future in as_completed(futures):
                entry = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001
                    logger.error("Failed to analyse {}: {}", entry.name, exc)
                    progress.advance(overall_task)
                    continue
                progress.advance(overall_task)
                if result is None:
                    continue
                analysis = result
                if history_dir is not None:
                    from nidhogg.output.history import append_finding  # noqa: PLC0415

                    append_finding(history_dir, build_document(analysis))
                if as_json:
                    progress.console.print(
                        json.dumps(build_document(analysis), indent=2),
                        markup=False,
                    )
                else:
                    if analysis.findings:
                        progress.console.print()
                        progress.console.print(
                            render_package_header(entry.name),
                            markup=False,
                        )
                    progress.console.print(
                        render_package_result(analysis, display_name=entry.name),
                        markup=False,
                    )
```

- [ ] **Step 9: Update docstrings mentioning confidence**

Search for and update docstrings in `_analyse_one()`, `_run_analyze()`, `_run_batch()`, `_run_fetch()` that mention "raise confidence for Let's Encrypt issuers".

- [ ] **Step 10: Run CLI tests**

Run: `uv run pytest tests/test_cli.py -v`
Expected: Tests checking for "score" in output or Verdict handling will fail

- [ ] **Step 11: Update test_cli.py**

Update tests that check for "score" in output or test exit codes based on malicious verdict.

- [ ] **Step 12: Commit**

```bash
git add nidhogg/cli.py tests/test_cli.py
git commit -m "refactor: remove classifier and verdict from CLI"
```

---

### Task 11: Update Web Interface

**Files:**
- Modify: `site/index.html:40-54`
- Modify: `site/app.js:79-144`
- Modify: `site/data/results.json`

**Interfaces:**
- Consumes: Updated JSON format without score/confidence/risk_level
- Produces: Web interface that displays findings without those fields

- [ ] **Step 1: Update index.html - remove Score and Conf. columns**

Edit `site/index.html`, remove the Score and Conf. columns from the thead:

```html
<div class="table-scroll">
  <table class="results">
    <thead>
      <tr>
        <th scope="col">Package</th>
        <th scope="col">Analyzed</th>
        <th scope="col">File:line</th>
        <th scope="col" class="col-url">URL</th>
        <th scope="col">Layer</th>
        <th scope="col">Method</th>
        <th scope="col">Threat</th>
      </tr>
    </thead>
    <tbody id="resultsBody"></tbody>
  </table>
</div>
```

Also remove the "Malicious only" toggle since there's no risk_level:

```html
<div class="controls">
  <input
    type="search"
    id="search"
    class="search"
    placeholder="Search package…"
    aria-label="Search package"
  />
</div>
```

- [ ] **Step 2: Update app.js - remove statusBadge()**

Delete the `statusBadge()` function entirely (lines 79-85).

- [ ] **Step 3: Update app.js - update findingCells()**

Remove confidence from the cells:

```javascript
function findingCells(finding) {
  const file = el("td", "cell-mono", `${finding.file}:${finding.line}`);
  const url = el("td", "cell-url", finding.url);
  const layer = el("td", "cell-mono", finding.layer);
  const method = el("td", "cell-mono", finding.method);
  const threat = el("td", "cell-mono", finding.domain_threat ?? "—");
  return [file, url, layer, method, threat];
}
```

- [ ] **Step 4: Update app.js - update emptyFindingCells()**

Remove the confidence cell:

```javascript
function emptyFindingCells() {
  return [
    el("td", "cell-mono cell-muted", "—"),
    el("td", "cell-url cell-muted", "—"),
    el("td", "cell-mono cell-muted", "—"),
    el("td", "cell-mono cell-muted", "—"),
    el("td", "cell-mono cell-muted", "—"),
  ];
}
```

- [ ] **Step 5: Update app.js - update renderResultsTable()**

Remove score cell and status badge:

```javascript
function renderResultsTable(packages) {
  const tbody = document.getElementById("resultsBody");
  tbody.replaceChildren();

  packages.forEach((pkg, pkgIndex) => {
    const rowCount = Math.max(pkg.findings.length, 1);
    const groupClass = pkgIndex % 2 === 0 ? "group-a" : "group-b";

    for (let i = 0; i < rowCount; i += 1) {
      const row = el("tr", `result-row ${groupClass}`);
      row.dataset.pkg = cssEscape(pkg.name);

      if (i === 0) {
        const nameCell = el("td", "cell-name", pkg.name);
        const dateCell = el(
          "td",
          "cell-mono cell-date",
          dateTimeFmt.format(new Date(pkg.analyzed_at)),
        );
        if (rowCount > 1) {
          [nameCell, dateCell].forEach((cell) => {
            cell.rowSpan = rowCount;
          });
        }
        row.append(nameCell, dateCell);
      }

      const cells = pkg.findings.length > 0 ? findingCells(pkg.findings[i]) : emptyFindingCells();
      row.append(...cells);
      tbody.appendChild(row);
    }
  });
}
```

- [ ] **Step 6: Update app.js - update applyFilters()**

Remove malicious-only filter:

```javascript
function applyFilters(packages, query) {
  const needle = query.trim().toLowerCase();
  return packages.filter((pkg) => {
    if (needle && !pkg.name.toLowerCase().includes(needle)) return false;
    return true;
  });
}
```

Update the `refresh()` function call:

```javascript
function refresh() {
  const filtered = applyFilters(data.packages, searchInput.value);
  renderResultsTable(filtered);
  emptyState.hidden = filtered.length !== 0;
}
```

Remove the `onlyMaliciousInput` event listener:

```javascript
const searchInput = document.getElementById("search");
const emptyState = document.getElementById("emptyState");

function refresh() {
  const filtered = applyFilters(data.packages, searchInput.value);
  renderResultsTable(filtered);
  emptyState.hidden = filtered.length !== 0;
}

refresh();
searchInput.addEventListener("input", refresh);
```

- [ ] **Step 7: Update site/data/results.json**

Remove `score`, `risk_level` from packages and `confidence` from findings. Example updated structure:

```json
{
  "generated_at": "2026-07-15T12:00:00Z",
  "stats": {
    "total_packages": 1245,
    "malicious": 4,
    "clean": 1241
  },
  "packages": [
    {
      "name": "requests-fork-utils",
      "analyzed_at": "2026-07-15T11:58:03Z",
      "total_findings": 0,
      "findings": []
    },
    {
      "name": "colorprint-lite",
      "analyzed_at": "2026-07-15T11:40:11Z",
      "total_findings": 1,
      "findings": [
        {
          "url": "https://pypi.org/simple",
          "file": "setup.py",
          "line": 6,
          "layer": "regex",
          "method": "literal",
          "domain_threat": null
        }
      ]
    }
  ]
}
```

Note: Keep `stats.malicious` and `stats.clean` for now as they're still displayed in the stats line. These will need to be updated when the data is regenerated.

- [ ] **Step 8: Test the web interface**

Serve the site directory and verify it works:

```bash
cd site && python3 -m http.server 8000
```

Open http://localhost:8000 in a browser and verify:
- No Score or Conf. columns
- No "Malicious only" toggle
- Findings display correctly with URL, layer, method, threat

- [ ] **Step 9: Commit**

```bash
git add site/
git commit -m "refactor: remove score and confidence from web interface"
```

---

### Task 12: Update Remaining Tests

**Files:**
- Modify: `tests/test_walker.py`
- Modify: `tests/test_integration.py`

**Interfaces:**
- Consumes: All updated modules
- Produces: All tests passing

- [ ] **Step 1: Update test_walker.py**

Remove `confidence` parameter from any `_finding()` or `UrlFinding()` calls in test fixtures.

- [ ] **Step 2: Update test_integration.py**

Update any tests that check for score, confidence, or verdict in the output.

- [ ] **Step 3: Run full test suite**

Run: `uv run pytest`
Expected: All tests pass

- [ ] **Step 4: Run type checking**

Run: `uv run mypy`
Expected: No type errors

- [ ] **Step 5: Run linting**

Run: `uv run ruff check`
Expected: No lint errors

- [ ] **Step 6: Run formatting check**

Run: `uv run ruff format --check`
Expected: No formatting issues

- [ ] **Step 7: Commit any remaining fixes**

```bash
git add tests/
git commit -m "test: update remaining tests for score/confidence removal"
```

---

### Task 13: Final Verification

**Files:**
- All modified files

**Interfaces:**
- Consumes: Complete implementation
- Produces: Verified working system

- [ ] **Step 1: Run complete verification**

```bash
uv run ruff check && uv run ruff format --check && uv run mypy && uv run pytest
```

Expected: All checks pass

- [ ] **Step 2: Test CLI manually**

```bash
uv run nidhogg.py analyze tests/fixtures/pkg_basic
```

Expected: Output shows findings without score or confidence

- [ ] **Step 3: Test JSON output**

```bash
uv run nidhogg.py analyze tests/fixtures/pkg_basic --json
```

Expected: JSON output without score, confidence, or risk_level

- [ ] **Step 4: Verify no orphaned references**

```bash
grep -r "confidence" nidhogg/ tests/ site/
grep -r "score" nidhogg/ tests/ site/
grep -r "Verdict" nidhogg/ tests/
grep -r "classify" nidhogg/ tests/
```

Expected: Only legitimate uses (e.g., in comments about future work)

- [ ] **Step 5: Create final commit**

```bash
git add -A
git commit -m "refactor: complete removal of score and confidence"
```
