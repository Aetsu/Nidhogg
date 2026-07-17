# Terminal Output Unification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unify all human-facing terminal output of the Nidhogg CLI under a single `rich`-based `output/renderer.py` module, eliminating manual ANSI codes and the duplicated printing logic between monitor and the rest of the CLI.

**Architecture:** A new `nidhogg/output/renderer.py` returns `rich` renderables (`Text`, `Table`, `Group`, `Progress`) consumed by `cli.py` through one shared `Console` built from `sys.stdout` (TTY decides color). `output/writer.py` is reduced to JSON serialization only. Monitor's progress/status/countdown helpers move into `renderer.py` so single, batch, and monitor share one rendering path.

**Tech Stack:** Python 3.14, `rich>=15.0.0` (already a dependency), `loguru`, `pytest`, `ruff` (ALL rules), `mypy` strict.

## Global Constraints

- **Python 3.14**, `uv` for everything (never `pip`).
- **ruff `select = ["ALL"]`** with the ignores listed in `pyproject.toml`; tests have per-file ignores (see `pyproject.toml:40`).
- **mypy strict** (`warn_return_any`, `warn_unused_ignores`, `check_untyped_defs`).
- **No `print()` for human output** after migration — use `console.print(renderable)`. The `# noqa: T201` silencers on the error-path `print(..., file=sys.stderr)` lines stay.
- **No new dependencies.** `rich` is already in `pyproject.toml:7`.
- **JSON path untouched:** `build_document`, `write_results`, `_serialise_finding`, `_risk_level` stay in `writer.py` and keep their current signatures.
- **No `--color` flag.** TTY decides; non-TTY emits plain text (no ANSI) via `color_system=None`.
- **`time.sleep` must be called at least once per monitor iteration** even with `--interval 0` (tests patch `time.sleep` to raise `KeyboardInterrupt`).
- **Style strings** use rich style names: `"bold red"`, `"yellow"`, `"dim"`, `"green"`, `"bold"`.
- **Score/risk thresholds** are read from `load_scoring_config().thresholds` (`high_display`, `medium_display`, `malicious_url`) — same as today. The score-bar color thresholds `0.85`/`0.5` are literals (same as current `_score_bar`).
- **Verification command** after every task: `uv run ruff check && uv run ruff format --check && uv run mypy && uv run pytest`.

---

## File Structure

- **Create** `nidhogg/output/renderer.py` — all human rendering (`rich` renderables).
- **Create** `tests/test_renderer.py` — tests for every `renderer.py` function.
- **Modify** `nidhogg/output/writer.py` — delete `format_results`, `format_batch_summary`, `_fmt_finding`, `_score_bar`, `_c`, and the ANSI constants. Keep `_risk_level`, `build_document`, `write_results`, `_serialise_finding`.
- **Modify** `nidhogg/cli.py` — replace `print(format_results(...))` / `print(format_batch_summary(...))` with `console.print(render_*(...))`; route monitor through `renderer` helpers; build one `Console` via `make_console()`.
- **Modify** `tests/test_output_writer.py` — delete the `format_results` tests (lines 197–240); they move to `test_renderer.py`. Keep all JSON/`write_results` tests.
- **No changes** to `nidhogg/output/history.py`, `nidhogg/scoring.py`, `nidhogg/classifier.py`, `nidhogg/core/models.py`, or any `--json`/`--output` behavior.

---

## Task 1: Scaffold `renderer.py` with `make_console`, `render_empty`, `render_score_bar`

**Files:**
- Create: `nidhogg/output/renderer.py`
- Test: `tests/test_renderer.py`

**Interfaces:**
- Produces:
  - `make_console(stream: TextIO | None = None) -> Console`
  - `render_empty(analysis: PackageAnalysis, *, display_name: str | None = None) -> Text`
  - `render_score_bar(score: float) -> Text`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_renderer.py`:

```python
"""Tests for output/renderer.py."""

from __future__ import annotations

import io
from pathlib import Path

from nidhogg.core.models import PackageAnalysis
from nidhogg.output.renderer import make_console, render_empty, render_score_bar


def _pkg(tmp_path: Path, name: str = "testpkg") -> PackageAnalysis:
    return PackageAnalysis(name=name, path=tmp_path)


def _capture(*renderables: object) -> str:
    console = make_console(io.StringIO())
    for r in renderables:
        console.print(r)
    return console.export_text()


def test_make_console_no_ansi_when_not_a_tty():
    console = make_console(io.StringIO())
    assert console.color_system is None


def test_render_empty_shows_name_and_message(tmp_path: Path):
    text = _capture(render_empty(_pkg(tmp_path, "evilpkg")))
    assert "evilpkg" in text
    assert "no URLs found" in text
    assert "●" in text


def test_render_empty_uses_display_name_override(tmp_path: Path):
    text = _capture(render_empty(_pkg(tmp_path), display_name="override"))
    assert "override" in text


def test_render_score_bar_shows_filled_blocks_and_pct():
    text = _capture(render_score_bar(0.82))
    assert "82%" in text
    assert "█" in text
    assert "░" in text


def test_render_score_bar_full_score():
    text = _capture(render_score_bar(1.0))
    assert "100%" in text
    assert "░" not in text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_renderer.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'nidhogg.output.renderer'`.

- [ ] **Step 3: Write minimal implementation**

Create `nidhogg/output/renderer.py`:

```python
"""Rich-based human presentation for Nidhogg CLI output.

This module returns rich renderables (Text, Table, Group, Progress) consumed by
``cli.py`` through a single shared ``Console``. JSON serialization lives in
``writer.py``; this module never emits JSON.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from rich.console import Console
from rich.text import Text

if TYPE_CHECKING:
    from collections.abc import TextIO

    from nidhogg.core.models import PackageAnalysis


def make_console(stream: TextIO | None = None) -> Console:
    """Build the shared CLI console.

    When *stream* is a terminal, colors are emitted; otherwise (pipes, files,
    CI) ``color_system`` is ``None`` so rich prints plain text with no ANSI
    escapes.

    Args:
        stream: Output stream; defaults to ``sys.stdout``.

    Returns:
        A configured ``rich.console.Console``.
    """
    stream = stream or sys.stdout
    is_tty = getattr(stream, "isatty", lambda: False)()
    return Console(
        file=stream,
        force_terminal=is_tty,
        color_system="auto" if is_tty else None,
        highlight=False,
    )


def render_empty(
    analysis: PackageAnalysis,
    *,
    display_name: str | None = None,
) -> Text:
    """Render the green one-liner shown when a package has no URL findings.

    Args:
        analysis: Completed package analysis.
        display_name: Override the package name in the output.

    Returns:
        A green ``Text`` like ``"● name: no URLs found"``.
    """
    name = display_name or analysis.name
    return Text(f"● {name}: no URLs found", style="green")


def render_score_bar(score: float) -> Text:
    """Render *score* as a 10-block bar followed by the percentage.

    Args:
        score: Value in ``[0.0, 1.0]``.

    Returns:
        A ``Text`` like ``"████████░░  82%"`` colored by risk band.
    """
    filled = round(score * 10)
    bar = "█" * filled + "░" * (10 - filled)
    pct = f"{score * 100:.0f}%"
    style = "bold red" if score >= 0.85 else ("yellow" if score >= 0.5 else "dim")
    return Text(f"{bar}  {pct}", style=style)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_renderer.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Lint, format, typecheck**

Run: `uv run ruff check && uv run ruff format && uv run mypy`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add nidhogg/output/renderer.py tests/test_renderer.py
git commit -m "feat(output): add renderer module with console, empty, score bar"
```

---

## Task 2: `render_findings_table` and `render_package_header`

**Files:**
- Modify: `nidhogg/output/renderer.py`
- Test: `tests/test_renderer.py`

**Interfaces:**
- Consumes: `render_score_bar` (from Task 1).
- Produces:
  - `render_findings_table(findings: list[UrlFinding], pkg_path: Path) -> Table`
  - `render_package_header(name: str, verdict: Verdict, score: float) -> Text`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_renderer.py` (add imports first):

```python
from nidhogg.classifier import Verdict
from nidhogg.core.models import (
    AnalysisLayer,
    DetectionMethod,
    DomainThreatCategory,
    UrlFinding,
)
from nidhogg.output.renderer import render_findings_table, render_package_header


def _finding(
    tmp_path: Path,
    url: str = "https://c2.evil.example.com/beacon",
    confidence: float = 0.95,
    method: DetectionMethod = DetectionMethod.LITERAL,
    layer: AnalysisLayer = AnalysisLayer.AST,
    lineno: int = 1,
) -> UrlFinding:
    return UrlFinding(
        value=url,
        filepath=tmp_path / "module.py",
        lineno=lineno,
        layer=layer,
        method=method,
        confidence=confidence,
    )


def test_findings_table_shows_loc_method_conf_url(tmp_path: Path):
    f = _finding(tmp_path)
    text = _capture(render_findings_table([f], tmp_path))
    assert "module.py:1" in text
    assert "literal" in text
    assert "0.95" in text
    assert "https://c2.evil.example.com/beacon" in text


def test_findings_table_shows_le_tag_for_lets_encrypt(tmp_path: Path):
    f = _finding(tmp_path)
    f.cert_issuer = "Let's Encrypt"
    text = _capture(render_findings_table([f], tmp_path))
    assert "[LE]" in text


def test_findings_table_omits_le_tag_for_other_issuer(tmp_path: Path):
    f = _finding(tmp_path)
    f.cert_issuer = "DigiCert Inc"
    text = _capture(render_findings_table([f], tmp_path))
    assert "[LE]" not in text


def test_findings_table_shows_domain_threat_tag_uppercase(tmp_path: Path):
    f = _finding(tmp_path)
    f.domain_threat = DomainThreatCategory.SHORTENER
    text = _capture(render_findings_table([f], tmp_path))
    assert "[SHORTENER]" in text


def test_findings_table_omits_bracket_tags_when_none(tmp_path: Path):
    f = _finding(tmp_path)
    f.cert_issuer = None
    f.domain_threat = None
    text = _capture(render_findings_table([f], tmp_path))
    assert "[" not in text


def test_findings_table_sorts_by_confidence_desc(tmp_path: Path):
    high = _finding(tmp_path, url="https://high.example.com", confidence=0.99)
    low = _finding(tmp_path, url="https://low.example.com", confidence=0.10)
    text = _capture(render_findings_table([low, high], tmp_path))
    assert text.index("high.example.com") < text.index("low.example.com")


def test_package_header_malicious_shows_name_and_verdict():
    text = _capture(render_package_header("evilpkg", Verdict.MALICIOUS, 0.95))
    assert "evilpkg" in text
    assert "MALICIOUS" in text


def test_package_header_clean_shows_name_and_verdict():
    text = _capture(render_package_header("cleanpkg", Verdict.NOT_MALICIOUS, 0.1))
    assert "cleanpkg" in text
    assert "CLEAN" in text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_renderer.py -v`
Expected: FAIL with `ImportError: cannot import name 'render_findings_table'`.

- [ ] **Step 3: Write minimal implementation**

Append to `nidhogg/output/renderer.py`. Update the `TYPE_CHECKING` block and imports first:

```python
from pathlib import Path

from rich.table import Table
from rich.text import Text

from nidhogg.classifier import Verdict
from nidhogg.scoring import load_scoring_config

if TYPE_CHECKING:
    from nidhogg.core.models import PackageAnalysis, UrlFinding
```

Then the functions:

```python
def render_findings_table(findings: list[UrlFinding], pkg_path: Path) -> Table:
    """Render URL findings as a borderless rich table.

    Columns: LOC, Method, Conf, URL. Rows are sorted by confidence descending.
    Inline ``[LE]`` (Let's Encrypt issuer) and ``[<THREAT>]`` tags are appended
    to the URL cell with the same semantics as the legacy ``_fmt_finding``.

    Args:
        findings: Findings to render.
        pkg_path: Package root used to relativise file paths.

    Returns:
        A borderless ``rich.table.Table``.
    """
    thresholds = load_scoring_config().thresholds
    table = Table(box=None, show_header=False, pad_edge=False, expand=False)
    table.add_column("LOC", no_wrap=True)
    table.add_column("Method", no_wrap=True)
    table.add_column("Conf", no_wrap=True)
    table.add_column("URL")

    for f in sorted(findings, key=lambda x: x.confidence, reverse=True):
        try:
            rel = str(f.filepath.relative_to(pkg_path))
        except ValueError:
            rel = str(f.filepath)
        loc = Text(f"{rel}:{f.lineno}")
        method = Text(f.method.value, style="dim")
        conf = f.confidence
        conf_style = (
            "bold red"
            if conf >= thresholds.high_display
            else ("yellow" if conf >= thresholds.medium_display else "dim")
        )
        conf_text = Text(f"{conf:.2f}", style=conf_style)
        url = Text(f.value)
        if f.cert_issuer is not None and "Let's Encrypt" in f.cert_issuer:
            url.append(" [LE]", style="yellow")
        if f.domain_threat is not None:
            url.append(
                f" [{f.domain_threat.value.upper()}]",
                style="bold red",
            )
        table.add_row(loc, method, conf_text, url)
    return table


def render_package_header(name: str, verdict: Verdict, score: float) -> Text:
    """Render the per-package header used in batch and monitor output.

    Args:
        name: Package display name.
        verdict: Final verdict — drives color and label.
        score: Package score (unused for color today, kept for future use and
            to match the caller's available data).

    Returns:
        A ``Text`` like ``"── evilpkg [MALICIOUS]"`` colored by verdict.
    """
    del score
    if verdict is Verdict.MALICIOUS:
        label = "MALICIOUS"
        style = "bold red"
    else:
        label = "CLEAN"
        style = "green"
    line = Text()
    line.append(f"── {name} ", style=style)
    line.append(f"[{label}]", style=style)
    return line
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_renderer.py -v`
Expected: PASS (13 tests total now).

- [ ] **Step 5: Lint, format, typecheck**

Run: `uv run ruff check && uv run ruff format && uv run mypy`
Expected: clean. If ruff complains about the `del score` (ARG002), prefer `del score` over a noqa — both are acceptable; pick `del score`.

- [ ] **Step 6: Commit**

```bash
git add nidhogg/output/renderer.py tests/test_renderer.py
git commit -m "feat(output): add findings table and package header renderers"
```

---

## Task 3: `render_package_result` (composes Task 1 + Task 2)

**Files:**
- Modify: `nidhogg/output/renderer.py`
- Test: `tests/test_renderer.py`

**Interfaces:**
- Consumes: `render_empty`, `render_score_bar`, `render_findings_table`, `_risk_level` (from `writer.py`).
- Produces:
  - `render_package_result(analysis: PackageAnalysis, *, display_name: str | None = None) -> Group | Text`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_renderer.py`:

```python
from nidhogg.classifier import classify
from nidhogg.output.renderer import render_package_result


def test_package_result_no_findings_returns_empty_line(tmp_path: Path):
    text = _capture(render_package_result(_pkg(tmp_path)))
    assert "●" in text
    assert "no URLs found" in text


def test_package_result_shows_header_fields(tmp_path: Path):
    f = _finding(tmp_path)
    analysis = _pkg(tmp_path, findings=[f])
    classify(analysis)
    text = _capture(render_package_result(analysis))
    assert "package  testpkg" in text
    assert "path     " in text
    assert "risk     " in text
    assert "score    " in text
    assert "findings 1" in text
    assert "URLs:" in text


def test_package_result_malicious_risk_label(tmp_path: Path):
    f = _finding(tmp_path, confidence=0.99)
    analysis = _pkg(tmp_path, findings=[f])
    classify(analysis)
    text = _capture(render_package_result(analysis))
    assert "MALICIOUS" in text


def test_package_result_clean_risk_label_when_low(tmp_path: Path):
    f = _finding(tmp_path, confidence=0.20)
    analysis = _pkg(tmp_path, findings=[f])
    classify(analysis)
    text = _capture(render_package_result(analysis))
    assert "CLEAN" in text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_renderer.py -v`
Expected: FAIL with `ImportError: cannot import name 'render_package_result'`.

- [ ] **Step 3: Write minimal implementation**

Append to `nidhogg/output/renderer.py`. Add imports:

```python
from rich.console import Console, Group
```

(extend the existing `from rich.console import Console` line) and:

```python
from nidhogg.output.writer import _risk_level
```

inside the `TYPE_CHECKING` block is wrong (it's used at runtime) — add it to the top-level imports after `from nidhogg.scoring import load_scoring_config`. Then:

```python
def render_package_result(
    analysis: PackageAnalysis,
    *,
    display_name: str | None = None,
) -> Group | Text:
    """Render the full human-readable block for one package.

    When there are no findings, delegates to :func:`render_empty`. Otherwise
    returns a ``Group`` of the header lines, score bar, and findings table.

    Args:
        analysis: Completed (classified) package analysis.
        display_name: Override the package name in the header.

    Returns:
        A ``Group`` of renderables, or a ``Text`` for the empty case.
    """
    if not analysis.findings:
        return render_empty(analysis, display_name=display_name)

    risk = _risk_level(analysis)
    risk_style = "bold red" if risk == "malicious" else "green"

    name = display_name or analysis.name

    score_line = Text("score    ")
    score_line.append_text(render_score_bar(analysis.score))

    lines: list[Text] = [
        Text("package  ").append(name, style="bold"),
        Text("path     ").append(str(analysis.path), style="dim"),
        Text(""),
        Text("risk     ").append(risk.upper(), style=risk_style),
        score_line,
        Text(f"findings {len(analysis.findings)}"),
        Text(""),
        Text("URLs:", style="bold"),
    ]
    return Group(*lines, render_findings_table(analysis.findings, analysis.path))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_renderer.py -v`
Expected: PASS (17 tests).

- [ ] **Step 5: Lint, format, typecheck**

Run: `uv run ruff check && uv run ruff format && uv run mypy`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add nidhogg/output/renderer.py tests/test_renderer.py
git commit -m "feat(output): add render_package_result composing header and table"
```

---

## Task 4: `render_batch_summary`

**Files:**
- Modify: `nidhogg/output/renderer.py`
- Test: `tests/test_renderer.py`

**Interfaces:**
- Consumes: nothing from earlier tasks (the risk level string arrives in each tuple).
- Produces:
  - `render_batch_summary(results: list[tuple[PackageAnalysis, str]]) -> Group`
    (the `str` is the risk level per package, matching `format_batch_summary`'s input today).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_renderer.py`:

```python
from nidhogg.output.renderer import render_batch_summary


def _classified(tmp_path: Path, name: str, findings: list[UrlFinding]) -> tuple[PackageAnalysis, str]:
    analysis = PackageAnalysis(name=name, path=tmp_path / name, findings=findings)
    (tmp_path / name).mkdir(exist_ok=True)
    classify(analysis)
    from nidhogg.output.writer import _risk_level
    return analysis, _risk_level(analysis)


def test_batch_summary_counts_by_risk(tmp_path: Path):
    mal = _classified(tmp_path, "mal", [_finding(tmp_path, confidence=0.99)])
    clean = _classified(tmp_path, "clean", [_finding(tmp_path, confidence=0.10)])
    text = _capture(render_batch_summary([mal, clean]))
    assert "BATCH SUMMARY" in text
    assert "packages analysed   2" in text
    assert "MALICIOUS" in text
    assert "CLEAN" in text


def test_batch_summary_lists_flagged_packages_above_threshold(tmp_path: Path):
    high = _classified(tmp_path, "high", [_finding(tmp_path, confidence=0.95)])
    low = _classified(tmp_path, "low", [_finding(tmp_path, confidence=0.10)])
    text = _capture(render_batch_summary([high, low]))
    assert "high" in text
    assert "low" not in text.split("packages with score")[1]


def test_batch_summary_total_url_findings(tmp_path: Path):
    a = _classified(
        tmp_path,
        "a",
        [_finding(tmp_path), _finding(tmp_path, url="https://x.example.com")],
    )
    text = _capture(render_batch_summary([a]))
    assert "url findings        2" in text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_renderer.py -v`
Expected: FAIL with `ImportError: cannot import name 'render_batch_summary'`.

- [ ] **Step 3: Write minimal implementation**

Append to `nidhogg/output/renderer.py`:

```python
_RISK_MALICIOUS = "malicious"
_RISK_CLEAN = "clean"
_BATCH_SCORE_THRESHOLD = 0.50


def render_batch_summary(
    results: list[tuple[PackageAnalysis, str]],
) -> Group:
    """Render the human-readable summary of a batch run.

    Mirrors the legacy ``format_batch_summary``: counts per risk level, total
    URL findings, and a list of packages above the score threshold grouped by
    risk.

    Args:
        results: ``(analysis, risk_level)`` pairs, one per package.

    Returns:
        A ``Group`` of ``Text`` renderables.
    """
    total = len(results)
    counts: dict[str, int] = {_RISK_MALICIOUS: 0, _RISK_CLEAN: 0}
    total_url_findings = 0
    flagged: list[tuple[str, str, float]] = []

    for analysis, risk in results:
        counts[risk] = counts.get(risk, 0) + 1
        total_url_findings += len(analysis.findings)
        if analysis.score > _BATCH_SCORE_THRESHOLD:
            flagged.append((analysis.name, risk, analysis.score))

    sep = Text("─" * 50, style="dim")
    lines: list[Text] = [
        Text(""),
        sep,
        Text("BATCH SUMMARY", style="bold"),
        sep,
        Text(f"packages analysed   {total}"),
        Text(""),
        Text("by risk level:"),
        Text("  ").append("MALICIOUS", style="bold red").append(
            f"  {counts[_RISK_MALICIOUS]}"
        ),
        Text("  ").append("CLEAN    ", style="green").append(
            f"  {counts[_RISK_CLEAN]}"
        ),
        Text(""),
        Text(f"url findings        {total_url_findings}"),
    ]

    if flagged:
        risk_order = {_RISK_MALICIOUS: 0, _RISK_CLEAN: 1}
        flagged.sort(key=lambda t: (risk_order.get(t[1], 9), -t[2]))
        lines.append(Text(""))
        threshold_pct = int(_BATCH_SCORE_THRESHOLD * 100)
        lines.append(
            Text(f"packages with score > {threshold_pct}:", style="bold")
        )
        current_group = ""
        for name, risk, score in flagged:
            if risk != current_group:
                current_group = risk
                group_style = "bold red" if risk == _RISK_MALICIOUS else "green"
                lines.append(Text("  ").append(risk.upper(), style=group_style))
            lines.append(Text(f"    {name:<33}  {int(score * 100):>3}"))

    lines.append(sep)
    return Group(*lines)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_renderer.py -v`
Expected: PASS (20 tests).

- [ ] **Step 5: Lint, format, typecheck**

Run: `uv run ruff check && uv run ruff format && uv run mypy`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add nidhogg/output/renderer.py tests/test_renderer.py
git commit -m "feat(output): add render_batch_summary"
```

---

## Task 5: Monitor helpers — `render_progress`, `render_status`, `render_countdown`

**Files:**
- Modify: `nidhogg/output/renderer.py`
- Test: `tests/test_renderer.py`

**Interfaces:**
- Produces:
  - `render_progress(*, console: Console) -> Progress` — factory with fixed columns; the caller calls `progress.add_task(description, total=total)` and advances it.
  - `render_status(message: str, *, console: Console) -> AbstractContextManager[None]`
  - `render_countdown(interval: int, *, console: Console) -> None`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_renderer.py`:

```python
from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import patch

from nidhogg.output.renderer import (
    render_countdown,
    render_progress,
    render_status,
)


def test_render_progress_returns_progress_with_console():
    console = make_console(io.StringIO())
    progress = render_progress(console=console)
    assert progress.console is console
    assert hasattr(progress, "add_task")


def test_render_status_yields_and_uses_console_status():
    console = make_console(io.StringIO())
    called = {"n": 0}

    @contextmanager
    def fake_status(msg: str) -> Iterator[None]:
        called["n"] += 1
        called["msg"] = msg
        yield

    with patch.object(console, "status", fake_status):
        with render_status("Comprobando PyPI...", console=console):
            pass
    assert called["n"] == 1
    assert called["msg"] == "Comprobando PyPI..."


def test_render_countdown_negative_interval_calls_sleep_once_and_returns():
    console = make_console(io.StringIO())
    calls: list[float] = []

    def fake_sleep(seconds: float) -> None:
        calls.append(seconds)

    with patch("time.sleep", fake_sleep):
        render_countdown(-5, console=console)
    assert calls == [-5]


def test_render_countdown_zero_interval_calls_sleep_once():
    console = make_console(io.StringIO())
    calls: list[float] = []

    def fake_sleep(seconds: float) -> None:
        calls.append(seconds)

    with patch("time.sleep", fake_sleep):
        render_countdown(0, console=console)
    assert calls == [0]


def test_render_countdown_positive_ticks_each_second():
    console = make_console(io.StringIO())
    calls: list[float] = []

    def fake_sleep(seconds: float) -> None:
        calls.append(seconds)
        if len(calls) >= 2:
            raise KeyboardInterrupt

    with patch("time.sleep", fake_sleep):
        try:
            render_countdown(10, console=console)
        except KeyboardInterrupt:
            pass
    assert calls[0] == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_renderer.py -v`
Expected: FAIL with `ImportError: cannot import name 'render_progress'`.

- [ ] **Step 3: Write minimal implementation**

Append to `nidhogg/output/renderer.py`. Imports needed:

```python
import time
from collections.abc import Iterator
from contextlib import contextmanager

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TimeElapsedColumn,
)
```

(`time` and `contextmanager`/`Iterator` go at the top of the file with the other stdlib imports; the rich imports with the other rich imports.)

```python
def render_progress(*, console: Console) -> Progress:
    """Build the shared progress display used by the monitor.

    Columns: spinner, description, bar, M-of-N, elapsed. The caller is
    responsible for ``add_task(description, total=...)`` and ``advance``.

    Args:
        console: Console to render into.

    Returns:
        A ``rich.progress.Progress`` the caller enters with ``with``.
    """
    return Progress(
        SpinnerColumn(),
        "{task.description}",
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    )


@contextmanager
def render_status(message: str, *, console: Console) -> Iterator[None]:
    """Wrap ``console.status(message)`` as a context manager.

    Args:
        message: Status text.
        console: Console to show the spinner on.

    Yields:
        None for the duration of the status.
    """
    with console.status(message):
        yield


def render_countdown(interval: int, *, console: Console) -> None:
    """Sleep for *interval* seconds showing a live countdown spinner.

    Always sleeps at least once, even for ``interval <= 0``, so callers that
    patch ``time.sleep`` to raise ``KeyboardInterrupt`` keep working.

    Args:
        interval: Seconds to wait.
        console: Console to render the spinner on.
    """
    if interval <= 0:
        time.sleep(interval)
        return

    remaining = interval
    with Progress(SpinnerColumn(), "{task.description}", console=console) as progress:
        task_id = progress.add_task(
            f"Esperando nuevos paquetes... próxima comprobación en {remaining}s"
        )
        while remaining > 0:
            time.sleep(1)
            remaining -= 1
            progress.update(
                task_id,
                description=(
                    f"Esperando nuevos paquetes... próxima comprobación en {remaining}s"
                ),
            )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_renderer.py -v`
Expected: PASS (25 tests).

- [ ] **Step 5: Lint, format, typecheck**

Run: `uv run ruff check && uv run ruff format && uv run mypy`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add nidhogg/output/renderer.py tests/test_renderer.py
git commit -m "feat(output): add monitor progress, status, countdown helpers"
```

---

## Task 6: Wire `renderer` into single and batch CLI paths

**Files:**
- Modify: `nidhogg/cli.py` (functions `_run_analyze`, `_run_fetch`, `_run_batch`)
- Test: `tests/test_cli.py` (add a smoke test)

**Interfaces:**
- Consumes: `make_console`, `render_package_result`, `render_package_header`, `render_batch_summary` from `renderer.py`; `_risk_level` still from `writer.py`.

- [ ] **Step 1: Add a characterization test (locks current behavior)**

This task is a behavior-preserving refactor: the rendered output stays the
same, so there is no red phase. The test below captures the **current**
human-readable shape so the refactor in Steps 3–5 can't silently change it.
First, run it against the legacy code to confirm it passes today (baseline),
then keep it green throughout the refactor.

Append to `tests/test_cli.py`:

```python
def test_run_analyze_prints_result_block(tmp_path: Path, capsys):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "module.py").write_text(
        'x = "https://c2.evil.example.com/beacon"\n', encoding="utf-8"
    )
    exit_code = _run_analyze(pkg_dir, None, as_json=False, verbose=False)
    out = capsys.readouterr().out
    assert exit_code == 1
    assert "package" in out
    assert "pkg" in out
    assert "URLs:" in out
    assert "https://c2.evil.example.com/beacon" in out
    assert "score" in out
```

- [ ] **Step 2: Confirm the test passes on the current (legacy) code**

Run: `uv run pytest tests/test_cli.py::test_run_analyze_prints_result_block -v`
Expected: PASS today (baseline captured). If it fails, fix the assertion to
match the exact current output — the point is to lock current behavior before
refactoring.

- [ ] **Step 3: Rewire `_run_analyze`**

In `nidhogg/cli.py`, replace the import block (lines ~18–24) so it imports from `renderer` instead of the deleted `writer` functions. The new imports:

```python
from nidhogg.output.renderer import (
    make_console,
    render_batch_summary,
    render_package_header,
    render_package_result,
)
from nidhogg.output.writer import _risk_level, build_document, write_results
```

(Remove `format_batch_summary`, `format_results` from the `writer` import — they will be deleted in Task 8, but importing them now would still work; to keep the build green between tasks, leave them imported only if still referenced. They won't be after this step, so remove them.)

In `_run_analyze`, replace the tail (lines ~277–285) — the `if output is not None / elif as_json / else` block — with:

```python
    if output is not None:
        write_results(analysis, output)
    elif as_json:
        print(json.dumps(build_document(analysis), indent=2))  # noqa: T201
    else:
        console = make_console()
        console.print(render_package_result(analysis))

    return 0 if verdict is Verdict.NOT_MALICIOUS else 1
```

(Delete the `use_color = sys.stdout.isatty()` line.)

- [ ] **Step 4: Rewire `_run_fetch`**

Apply the same change to `_run_fetch`'s tail (lines ~421–429): replace the `else` branch with the same two lines (`make_console()` + `console.print(render_package_result(analysis))`), and remove its `use_color` line.

- [ ] **Step 5: Rewire `_run_batch`**

In `_run_batch`, replace the per-package print block (lines ~352–356) and the trailing summary (line ~364). Remove `use_color = sys.stdout.isatty()` (line ~325). New per-package block:

```python
        else:
            if analysis.findings:
                console.print()
                console.print(
                    render_package_header(
                        pkg_dir.name, verdict, analysis.score
                    )
                )
            console.print(
                render_package_result(analysis, display_name=pkg_dir.name)
            )
```

And the trailing summary (replace `print(format_batch_summary(batch_results, color=use_color))`):

```python
    if batch_results:
        console.print(render_batch_summary(batch_results))
```

Create one shared `console` near the top of `_run_batch`, right after `if not verbose: logger.remove()`:

```python
    console = make_console()
```

- [ ] **Step 6: Run all CLI tests**

Run: `uv run pytest tests/test_cli.py -v`
Expected: PASS (all existing tests + the new smoke test). The new test should now PASS.

- [ ] **Step 7: Lint, format, typecheck**

Run: `uv run ruff check && uv run ruff format && uv run mypy`
Expected: clean. If mypy complains about unused imports of `format_results`/`format_batch_summary`, they were already removed in Step 3.

- [ ] **Step 8: Commit**

```bash
git add nidhogg/cli.py tests/test_cli.py
git commit -m "refactor(cli): wire single and batch output through renderer"
```

---

## Task 7: Wire `renderer` into the monitor

**Files:**
- Modify: `nidhogg/cli.py` (functions `_process_entries_plain`, `_process_entries_rich`, `_run_monitor_iteration_rich`, `_wait_before_next_poll_rich`, `_analyse_with_progress`, `_run_monitor`)

**Interfaces:**
- Consumes: `make_console`, `render_package_header`, `render_package_result`, `render_progress`, `render_status`, `render_countdown` from `renderer.py`.

- [ ] **Step 1: Write a failing test**

This test forces the per-package header path by giving the fake analysis a
finding. Today the plain monitor path prints `=== newpkg ===`; after the
refactor it prints the renderer header `── newpkg [CLEAN]`. So `── newpkg` is
absent today (red) and present after (green).

Append to `tests/test_cli.py` (imports `capsys` is a fixture, no import
needed; `UrlFinding`, `AnalysisLayer`, `DetectionMethod` must be imported —
add them to the existing `from nidhogg.core.models import ...` line):

```python
def test_run_monitor_plain_path_prints_rendered_header(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """Non-TTY monitor path prints the renderer header, not `=== pkg ===`."""
    index_file = tmp_path / "state.json"
    fake_client = MagicMock()
    fake_client.current_serial.return_value = 100
    fake_client.entries_since.return_value = [
        ChangelogEntry(
            name="newpkg", version="", timestamp=1, action="create", serial=99
        )
    ]

    finding = UrlFinding(
        value="https://c2.evil.example.com/beacon",
        filepath=tmp_path / "module.py",
        lineno=1,
        layer=AnalysisLayer.AST,
        method=DetectionMethod.LITERAL,
        confidence=0.20,
    )
    fake_analysis = PackageAnalysis(name="newpkg", path=tmp_path, findings=[finding])

    def _fake_analyse(name, **kwargs):  # noqa: ARG001
        return fake_analysis, Verdict.NOT_MALICIOUS

    def _fake_sleep(seconds):  # noqa: ARG001
        raise KeyboardInterrupt

    with (
        patch("nidhogg.fetching.changelog.ChangelogClient", return_value=fake_client),
        patch("nidhogg.cli._analyse_new_package", _fake_analyse),
        patch("time.sleep", _fake_sleep),
        patch("sys.stdout.isatty", return_value=False),
    ):
        exit_code = _run_monitor(
            interval=0,
            index_file=index_file,
            concurrency=1,
            keep_download=None,
            as_json=False,
            history_dir=None,
            verbose=False,
        )
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "── newpkg" in out
    assert "=== newpkg ===" not in out
```

Add `import pytest` at the top of `tests/test_cli.py` if not present (needed for
the `pytest.CaptureFixture` annotation; if you prefer, drop the annotation and
just use `capsys` as the fixture parameter).

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py::test_run_monitor_plain_path_prints_rendered_header -v`
Expected: FAIL — today the plain path prints `=== newpkg ===` (via `_process_entries_plain`), so `assert "=== " not in out` fails.

- [ ] **Step 3: Rewire `_process_entries_plain`**

In `nidhogg/cli.py`, replace the per-result print block inside `_process_entries_plain` (lines ~498–504). Build a console at the top of the function:

```python
    console = make_console()
```

right after the `from concurrent.futures ...` import inside the function body. Replace the per-result block:

```python
            if as_json:
                print(json.dumps(build_document(analysis), indent=2))  # noqa: T201
            else:
                console.print(render_package_result(analysis, display_name=entry.name))
```

(No more `=== pkg ===` header here — the package result block already includes the package name. The `if analysis.findings:` blank line + `=== name ===` is dropped; the rendered block is self-contained. If you want the per-package header in monitor too, use `render_package_header(entry.name, _verdict, analysis.score)` when `analysis.findings` — but `_verdict` is discarded today; to keep it simple and match the spec's "cabecera richer por paquete", print the header when there are findings:)

Final shape for `_process_entries_plain` non-json branch:

```python
            if as_json:
                print(json.dumps(build_document(analysis), indent=2))  # noqa: T201
            else:
                if analysis.findings:
                    console.print()
                    console.print(
                        render_package_header(entry.name, _verdict, analysis.score)
                    )
                console.print(
                    render_package_result(analysis, display_name=entry.name)
                )
```

- [ ] **Step 4: Rewire `_process_entries_rich`**

Same change, but printing through `progress.console`:

```python
                if as_json:
                    progress.console.print(
                        json.dumps(build_document(analysis), indent=2),
                        markup=False,
                    )
                else:
                    if analysis.findings:
                        progress.console.print()
                        progress.console.print(
                            render_package_header(
                                entry.name, _verdict, analysis.score
                            ),
                            markup=False,
                        )
                    progress.console.print(
                        render_package_result(analysis, display_name=entry.name),
                        markup=False,
                    )
```

Also replace the `Progress(...)` construction (lines ~598–613) with `render_progress`:

```python
    with render_progress(console=console) as progress:
        overall_task = progress.add_task("Analizando paquetes", total=len(entries))
```

`render_progress` returns a `Progress` configured with columns; the caller calls `add_task`. Remove the now-unused imports of `BarColumn`, `MofNCompleteColumn`, `Progress`, `SpinnerColumn`, `TimeElapsedColumn` from inside `_process_entries_rich` (they're now in `renderer.py`). Add at the top of `cli.py`'s imports: `render_progress`, `render_status`, `render_countdown` to the `from nidhogg.output.renderer import (...)` block.

- [ ] **Step 5: Rewire `_run_monitor_iteration_rich`**

Replace `with console.status("Comprobando PyPI..."):` (line ~678) with:

```python
    with render_status("Comprobando PyPI...", console=console):
        current_serial = client.current_serial()
        entries = [e for e in client.entries_since(last_serial) if e.is_new_project]
```

- [ ] **Step 6: Rewire `_wait_before_next_poll_rich`**

Replace the entire body of `_wait_before_next_poll_rich` (lines ~696–728) with a single delegation:

```python
def _wait_before_next_poll_rich(interval: int, console: Console) -> None:
    """Sleep for *interval* seconds showing a live countdown spinner.

    Delegates to :func:`nidhogg.output.renderer.render_countdown`, which
    preserves the invariant that ``time.sleep`` is called at least once even
    when ``interval <= 0``.

    Args:
        interval: Seconds to wait before the next changelog poll.
        console: Rich console shared with the rest of the monitor loop.
    """
    render_countdown(interval, console=console)
```

Remove the now-unused `from rich.progress import Progress, SpinnerColumn` import inside that function.

- [ ] **Step 7: Rewire `_analyse_with_progress` (no change needed)**

`_analyse_with_progress` already uses the shared `progress` object. After Step 4 it receives a `Progress` from `render_progress`. Its signature already takes `progress: Progress`; keep the `from rich.progress import Progress` type import in the `TYPE_CHECKING` block. No code change required here.

- [ ] **Step 8: Run all CLI tests**

Run: `uv run pytest tests/test_cli.py -v`
Expected: PASS (including the new `test_run_monitor_plain_path_prints_rendered_header` and the existing `test_run_monitor_uses_rich_path_when_stdout_is_a_tty`).

- [ ] **Step 9: Lint, format, typecheck**

Run: `uv run ruff check && uv run ruff format && uv run mypy`
Expected: clean.

- [ ] **Step 10: Commit**

```bash
git add nidhogg/cli.py tests/test_cli.py
git commit -m "refactor(cli): route monitor output and progress through renderer"
```

---

## Task 8: Remove dead code from `writer.py` and migrate tests

**Files:**
- Modify: `nidhogg/output/writer.py`
- Modify: `tests/test_output_writer.py`

**Interfaces:** none (cleanup only).

- [ ] **Step 1: Confirm `format_results`/`format_batch_summary` have no remaining callers**

Run: `uv run ruff check`
Expected: no errors yet (they're public functions, ruff won't flag them). Then grep:

```bash
rg -n "format_results|format_batch_summary|_fmt_finding|_score_bar|_c\(" nidhogg/ tests/
```

Expected: only matches inside `writer.py` (definitions) and `tests/test_output_writer.py` (the tests being removed in Step 3). No `cli.py` references.

- [ ] **Step 2: Delete dead code from `writer.py`**

Remove from `nidhogg/output/writer.py`:
- Constants `_RST`, `_BOLD`, `_DIM`, `_RED`, `_GREEN`, `_YELLOW`, `_RISK_COLORS` (lines ~19–30).
- Functions `_c` (lines ~75–79), `_fmt_finding` (lines ~82–107), `_score_bar` (lines ~110–124), `format_results` (lines ~127–166), `format_batch_summary` (lines ~193–260).

Keep: module docstring, `from __future__ import annotations`, `import json`, the `TYPE_CHECKING` block, `_RISK_MALICIOUS`/`_RISK_CLEAN` (still used by `_risk_level`), `_risk_level`, `_serialise_finding`, `build_document`, `write_results`, and the `load_scoring_config` import.

- [ ] **Step 3: Migrate `tests/test_output_writer.py`**

Delete the entire `# format_results` section (lines 197–240 — the five `test_format_results_*` functions and the section comment). Keep all `write_results`/`build_document`/`_serialise_finding` tests (lines 1–195). Remove the now-unused imports if any become unused (`format_results` is imported on line 18 — drop it from the import; keep `write_results`).

The `format_results` behavior is now covered by `tests/test_renderer.py` (Tasks 2–4).

- [ ] **Step 4: Run the full suite**

Run: `uv run pytest -v`
Expected: PASS. `test_output_writer.py` has fewer tests but still covers JSON; `test_renderer.py` covers all rendering.

- [ ] **Step 5: Lint, format, typecheck**

Run: `uv run ruff check && uv run ruff format --check && uv run mypy`
Expected: clean.

- [ ] **Step 6: Final full verification**

Run: `uv run ruff check && uv run ruff format --check && uv run mypy && uv run pytest`
Expected: all green. This is the completion gate from `AGENTS.md`.

- [ ] **Step 7: Commit**

```bash
git add nidhogg/output/writer.py tests/test_output_writer.py
git commit -m "refactor(output): drop legacy ANSI formatters from writer, migrate tests"
```

---

## Self-Review (run after writing this plan — already done)

- **Spec coverage:** Every section of `2026-07-15-terminal-output-design.md` maps to a task. `make_console`+`render_empty`+`render_score_bar` → Task 1. `render_findings_table`+`render_package_header` → Task 2. `render_package_result` → Task 3. `render_batch_summary` → Task 4. `render_progress`+`render_status`+`render_countdown` → Task 5. Single/batch wiring → Task 6. Monitor wiring → Task 7. `writer.py` cleanup + test migration → Task 8. JSON untouched (Global Constraints). No-TTY plain text (Task 1 `make_console`). Compact layout (Task 3 Group). Per-package header replaces `=== pkg ===` (Tasks 6 & 7). `time.sleep`-at-least-once invariant (Task 5 `render_countdown` + test).
- **Placeholder scan:** none.
- **Type consistency:** `render_package_result -> Group | Text`, `render_batch_summary -> Group`, `render_findings_table -> Table`, `render_package_header -> Text`, `render_score_bar -> Text`, `render_empty -> Text`, `render_progress -> Progress`, `render_status` is a cm, `render_countdown -> None`. `_risk_level(analysis) -> str` consumed by Task 3 and Task 4 (via the `str` in the tuple). Consistent across tasks.
