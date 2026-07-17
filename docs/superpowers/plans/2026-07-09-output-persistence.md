# Output and Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in JSONL history log, a timestamped top-packages cache with a staleness warning, and a full text/JSON breakdown of typosquat signals to Nidhogg's output.

**Architecture:** A new `output/history.py` module appends result documents to dated JSONL files. `analysis/typosquat.py`'s cache file gains an optional `fetched_at` timestamp (backward-compatible with the legacy list-only format). `output/writer.py` grows its typosquat rendering to show every populated signal field. `cli.py` wires a `--history-dir` flag and a non-blocking cache-age warning.

**Tech Stack:** Python 3.14 stdlib only, pytest. Depends on the `TyposquatFinding` fields and `typosquat_config.py` added in `docs/superpowers/plans/2026-07-08-typosquat-metadata-signals.md` (implement that plan first).

## Global Constraints

- No new dependencies.
- Mypy strict: every function has full type hints including return types.
- Docstrings: Google style, on every public function.
- Run `uv run pytest`, `uv run ruff check`, `uv run ruff format --check`, and `uv run mypy` before each commit that finishes a task.
- History writing never raises — a failed write is logged and returns `None`, the analysis pipeline is unaffected.

---

### Task 1: `output/history.py` — append-only JSONL log

**Files:**
- Create: `nidhogg/output/history.py`
- Test: `tests/test_history.py`

**Interfaces:**
- Produces: `append_finding(history_dir: Path, document: dict[str, object]) -> Path | None`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_history.py`:

```python
"""Tests for output/history.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nidhogg.output.history import append_finding


def test_append_finding_creates_dated_file(tmp_path: Path):
    result = append_finding(tmp_path, {"package": {"name": "pkg"}})
    assert result is not None
    assert result.parent == tmp_path
    assert result.suffix == ".jsonl"


def test_append_finding_creates_missing_directory(tmp_path: Path):
    history_dir = tmp_path / "does" / "not" / "exist"
    result = append_finding(history_dir, {"package": {"name": "pkg"}})
    assert result is not None
    assert result.exists()


def test_append_finding_accumulates_across_calls(tmp_path: Path):
    append_finding(tmp_path, {"package": {"name": "a"}})
    result = append_finding(tmp_path, {"package": {"name": "b"}})
    assert result is not None
    lines = result.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["package"]["name"] == "a"
    assert json.loads(lines[1])["package"]["name"] == "b"


def test_append_finding_returns_none_on_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def _boom(*args: object, **kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(Path, "open", _boom)
    result = append_finding(tmp_path, {"package": {"name": "pkg"}})
    assert result is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_history.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'nidhogg.output.history'`.

- [ ] **Step 3: Implement**

Create `nidhogg/output/history.py`:

```python
"""Append-only JSONL history log for analysis results."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from pathlib import Path


def append_finding(history_dir: Path, document: dict[str, object]) -> Path | None:
    """Append *document* to today's JSONL history file under *history_dir*.

    Args:
        history_dir: Directory to store dated history files in. Created if
            it does not exist.
        document: The result document to append (e.g. from ``build_document``).

    Returns:
        The path written to, or ``None`` if the write failed (permissions,
        disk full, ...) — logged as a warning, never raised.
    """
    file_path = history_dir / f"{datetime.now(UTC).date().isoformat()}.jsonl"
    try:
        history_dir.mkdir(parents=True, exist_ok=True)
        with file_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(document, default=str) + "\n")
    except OSError as exc:
        logger.warning("Could not write history file {}: {}", file_path, exc)
        return None
    return file_path
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_history.py -v`
Expected: PASS, all 4 tests.

Run: `uv run ruff check nidhogg/output/history.py && uv run mypy nidhogg/output/history.py`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/output/history.py tests/test_history.py
git commit -m "feat(output): add append-only JSONL history log"
```

---

### Task 2: Timestamped top-packages cache

**Files:**
- Modify: `nidhogg/analysis/typosquat.py`
- Test: `tests/test_top_packages_cache.py` (new)

**Interfaces:**
- Produces: `top_packages_last_updated(path: Path | None = None) -> datetime | None`; `_load_top_packages`/`_load_top_packages_list` gain an optional `path` parameter; `update_top_packages()` now writes `{"fetched_at": ..., "packages": [...]}`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_top_packages_cache.py`:

```python
"""Tests for the top-packages cache format (legacy list vs timestamped dict)."""

from __future__ import annotations

import json
from pathlib import Path

from nidhogg.analysis.typosquat import _load_top_packages, top_packages_last_updated


def test_load_top_packages_legacy_list_format(tmp_path: Path):
    data_file = tmp_path / "top.json"
    data_file.write_text(json.dumps(["Requests", "NumPy"]), encoding="utf-8")
    names = _load_top_packages(data_file)
    assert "requests" in names
    assert "numpy" in names


def test_load_top_packages_current_dict_format(tmp_path: Path):
    data_file = tmp_path / "top.json"
    data_file.write_text(
        json.dumps({"fetched_at": "2026-01-01T00:00:00+00:00", "packages": ["Flask"]}),
        encoding="utf-8",
    )
    names = _load_top_packages(data_file)
    assert "flask" in names


def test_top_packages_last_updated_legacy_format_returns_none(tmp_path: Path):
    data_file = tmp_path / "top.json"
    data_file.write_text(json.dumps(["requests"]), encoding="utf-8")
    assert top_packages_last_updated(data_file) is None


def test_top_packages_last_updated_current_format_returns_timestamp(tmp_path: Path):
    data_file = tmp_path / "top.json"
    data_file.write_text(
        json.dumps({"fetched_at": "2026-01-01T00:00:00+00:00", "packages": ["flask"]}),
        encoding="utf-8",
    )
    result = top_packages_last_updated(data_file)
    assert result is not None
    assert result.year == 2026
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_top_packages_cache.py -v`
Expected: FAIL — `_load_top_packages` doesn't accept a `path` argument yet (`TypeError`), and `top_packages_last_updated` doesn't exist (`ImportError`).

- [ ] **Step 3: Implement**

In `nidhogg/analysis/typosquat.py`, update the top-of-file imports:

```python
from __future__ import annotations

import functools
import json
import re
from datetime import datetime
from typing import TYPE_CHECKING

from nidhogg.core.models import TyposquatFinding, TyposquatMethod
from nidhogg.typosquat_config import load_typosquat_config

if TYPE_CHECKING:
    from pathlib import Path
```

Replace the block containing `_load_top_packages` and `_load_top_packages_list` (originally lines 47-68) with:

```python
def _default_data_file() -> Path:
    """Path to the bundled top-packages JSON file.

    Returns:
        Absolute path to ``nidhogg/data/top_pypi_packages.json``.
    """
    from pathlib import Path as _Path  # noqa: PLC0415

    return _Path(__file__).parent.parent / "data" / "top_pypi_packages.json"


@functools.cache
def _load_top_packages_raw(path: Path | None = None) -> dict[str, object] | list[str]:
    """Load and cache the raw JSON content of the top-packages file.

    Args:
        path: Path to a custom top-packages JSON file. When ``None``, the
            file bundled with the package is used.

    Returns:
        Either a plain list of names (legacy format) or a dict with
        ``fetched_at``/``packages`` keys (current format).
    """
    data_file = path if path is not None else _default_data_file()
    raw = data_file.read_text(encoding="utf-8")
    return json.loads(raw)  # type: ignore[no-any-return]


def _extract_names(raw: dict[str, object] | list[str]) -> list[str]:
    """Extract the package name list from either the legacy or current format.

    Args:
        raw: The parsed JSON content, as returned by ``_load_top_packages_raw``.

    Returns:
        The list of package names.
    """
    if isinstance(raw, list):
        return raw
    return raw["packages"]  # type: ignore[return-value]


@functools.cache
def _load_top_packages(path: Path | None = None) -> frozenset[str]:
    """Load and cache the top PyPI package list, normalised.

    Args:
        path: Path to a custom top-packages JSON file. When ``None``, the
            file bundled with the package is used.

    Returns:
        Frozenset of normalised package names.
    """
    names = _extract_names(_load_top_packages_raw(path))
    return frozenset(_normalise(n) for n in names)


def _load_top_packages_list(path: Path | None = None) -> list[str]:
    """Return the top packages as a sorted list (for distance search).

    Args:
        path: Forwarded to ``_load_top_packages``.

    Returns:
        Sorted list of normalised package names.
    """
    return sorted(_load_top_packages(path))


def top_packages_last_updated(path: Path | None = None) -> datetime | None:
    """Return when the top-packages cache was last refreshed.

    Args:
        path: Path to a custom top-packages JSON file. When ``None``, the
            file bundled with the package is used.

    Returns:
        The ``fetched_at`` timestamp, or ``None`` when the file is in the
        legacy list-only format (no timestamp recorded).
    """
    raw = _load_top_packages_raw(path)
    if isinstance(raw, list):
        return None
    fetched_at = raw.get("fetched_at")
    if not isinstance(fetched_at, str):
        return None
    return datetime.fromisoformat(fetched_at)
```

Update `check_typosquatting`'s two call sites — they already call `_load_top_packages()` and `_load_top_packages_list()` with no arguments, which still works (default `path=None`); no change needed there.

Replace `update_top_packages` (originally lines 252-283):

```python
def update_top_packages() -> None:
    """Fetch the latest top-PyPI-packages list and overwrite the bundled file.

    Requires network access. Downloads from the canonical source at
    ``https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json``
    and writes the top 5000 package names, plus a ``fetched_at`` timestamp, to
    ``nidhogg/data/top_pypi_packages.json``.

    After updating, the in-memory caches are cleared so subsequent calls to
    ``check_typosquatting`` use the new data.
    """
    import urllib.request  # noqa: PLC0415
    from datetime import UTC  # noqa: PLC0415

    from loguru import logger  # noqa: PLC0415

    url = (
        "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
    )
    logger.info("Fetching top PyPI packages from {}", url)
    with urllib.request.urlopen(url) as resp:  # noqa: S310
        raw = resp.read().decode("utf-8")
    data: dict[str, object] = json.loads(raw)
    rows = data.get("rows", [])
    names = [str(r["project"]).lower() for r in rows[:5000]]  # type: ignore[index]

    payload = {
        "fetched_at": datetime.now(UTC).isoformat(),
        "packages": names,
    }
    dest = _default_data_file()
    dest.write_text(json.dumps(payload), encoding="utf-8")

    _load_top_packages.cache_clear()
    _load_top_packages_raw.cache_clear()
    logger.info("Updated top PyPI packages list with {} entries", len(names))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_top_packages_cache.py tests/test_typosquat.py -v`
Expected: PASS. The existing `test_typosquat.py` suite must still pass unchanged — it calls `check_typosquatting`, which uses the default (bundled, legacy list-format) cache file transparently.

Run: `uv run ruff check nidhogg/analysis/typosquat.py && uv run mypy nidhogg/analysis/typosquat.py`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/analysis/typosquat.py tests/test_top_packages_cache.py
git commit -m "feat(typosquat): timestamp the top-packages cache, support legacy format"
```

---

### Task 3: `[cache]` staleness threshold in `typosquat.toml`

**Files:**
- Modify: `nidhogg/data/typosquat.toml`
- Modify: `nidhogg/typosquat_config.py`
- Test: `tests/test_typosquat_config.py`

**Interfaces:**
- Produces: `TyposquatConfig.cache_max_age_days: int`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_typosquat_config.py`:

```python
def test_load_typosquat_config_default_cache_max_age_days():
    cfg = load_typosquat_config()
    assert cfg.cache_max_age_days == 30
```

Update the existing `test_load_typosquat_config_custom_path` test's fixture TOML string (it must now include a `[cache]` section or `_parse_config` will raise `KeyError`):

```python
def test_load_typosquat_config_custom_path(tmp_path: Path):
    custom = tmp_path / "typosquat.toml"
    custom.write_text(
        """
known_exceptions = [["request", "requests"]]

[levenshtein]
max_distance = 2

[confidence]
levenshtein = 0.6
transposition = 0.55
substitution = 0.55
affix = 0.35
pluralization = 0.4

[cache]
max_age_days = 30
""",
        encoding="utf-8",
    )
    cfg = load_typosquat_config(custom)
    assert cfg.max_distance == 2
    assert ("request", "requests") in cfg.known_exceptions
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_typosquat_config.py -v`
Expected: FAIL — `test_load_typosquat_config_default_cache_max_age_days` fails with `AttributeError: 'TyposquatConfig' object has no attribute 'cache_max_age_days'`.

- [ ] **Step 3: Implement**

In `nidhogg/data/typosquat.toml`, add at the end:

```toml
[cache]
# Warn (non-blocking) when the top-packages cache is older than this, in days.
max_age_days = 30
```

In `nidhogg/typosquat_config.py`, add the field to `TyposquatConfig`:

```python
@dataclass(frozen=True)
class TyposquatConfig:
    """Complete typosquat configuration loaded from typosquat.toml.

    Attributes:
        max_distance: Maximum Levenshtein distance to consider a name a
            typosquat of a top package.
        confidence: Base confidence value for each detection method.
        known_exceptions: Pairs of ``(candidate, target)`` normalised names
            that are never reported even if they match.
        cache_max_age_days: Age in days after which the top-packages cache
            is considered stale (used for a non-blocking CLI warning).
    """

    max_distance: int
    confidence: dict[TyposquatMethod, float]
    known_exceptions: frozenset[tuple[str, str]]
    cache_max_age_days: int
```

Update `_parse_config`:

```python
def _parse_config(data: dict[str, Any]) -> TyposquatConfig:
    """Build a :class:`TyposquatConfig` from a raw TOML dict.

    Args:
        data: Parsed TOML document as a plain dict.

    Returns:
        Fully populated :class:`TyposquatConfig` instance.
    """
    levenshtein: dict[str, Any] = data["levenshtein"]
    confidence_raw: dict[str, Any] = data["confidence"]
    exceptions_raw: list[list[str]] = data.get("known_exceptions", [])
    cache: dict[str, Any] = data["cache"]

    confidence = {
        TyposquatMethod(name): float(value) for name, value in confidence_raw.items()
    }
    known_exceptions = frozenset((pair[0], pair[1]) for pair in exceptions_raw)

    return TyposquatConfig(
        max_distance=int(levenshtein["max_distance"]),
        confidence=confidence,
        known_exceptions=known_exceptions,
        cache_max_age_days=int(cache["max_age_days"]),
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_typosquat_config.py -v`
Expected: PASS, all tests.

Run: `uv run ruff check nidhogg/typosquat_config.py nidhogg/data/typosquat.toml && uv run mypy nidhogg/typosquat_config.py`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/data/typosquat.toml nidhogg/typosquat_config.py tests/test_typosquat_config.py
git commit -m "feat(typosquat): add configurable cache staleness threshold"
```

---

### Task 4: Typosquat signal breakdown in `output/writer.py`

**Files:**
- Modify: `nidhogg/output/writer.py`
- Test: `tests/test_output_writer.py`

**Interfaces:**
- Consumes: `TyposquatFinding`'s metadata fields (from the typosquat-metadata-signals plan).
- Produces: `format_results` prints one extra line per populated signal; `build_document`'s `"typosquat"` dict includes every field.

- [ ] **Step 1: Write the failing tests**

In `tests/test_output_writer.py`, update the `_pkg` helper to accept a `typosquat` override, and add `format_results`/`build_document` to the imports:

```python
from nidhogg.core.models import (
    AnalysisLayer,
    DetectionMethod,
    PackageAnalysis,
    TyposquatFinding,
    TyposquatMethod,
    UrlFinding,
)
from nidhogg.output.writer import build_document, format_results, write_results


def _pkg(
    tmp_path: Path,
    findings: list[UrlFinding] | None = None,
    uses_dynamic: bool = False,
    typosquat: TyposquatFinding | None = None,
) -> PackageAnalysis:
    return PackageAnalysis(
        name="testpkg",
        path=tmp_path,
        findings=findings or [],
        uses_dynamic_execution=uses_dynamic,
        typosquat=typosquat,
    )
```

Append new test functions:

```python
def _enriched_typosquat() -> TyposquatFinding:
    return TyposquatFinding(
        package_name="requestz",
        similar_to="requests",
        distance=1,
        method=TyposquatMethod.LEVENSHTEIN,
        confidence=0.6,
        adjusted_confidence=0.85,
        description_similarity=0.72,
        classifier_overlap=0.4,
        shared_repo_url="https://github.com/psf/requests",
        completeness_delta=0.35,
        author_domain_age_days=4,
    )


def test_format_results_shows_base_confidence_only_when_not_enriched(tmp_path: Path):
    ts = TyposquatFinding(
        package_name="requestz",
        similar_to="requests",
        distance=1,
        method=TyposquatMethod.LEVENSHTEIN,
        confidence=0.6,
    )
    text = format_results(_pkg(tmp_path, typosquat=ts))
    assert "Confidence: 0.60" in text
    assert "adjusted" not in text
    assert "Shared repo" not in text


def test_format_results_shows_all_signals_when_enriched(tmp_path: Path):
    text = format_results(_pkg(tmp_path, typosquat=_enriched_typosquat()))
    assert "Confidence: 0.60 -> 0.85 (adjusted)" in text
    assert "Description similarity: 0.72" in text
    assert "Keyword/classifier overlap: 0.40" in text
    assert "Shared repo: https://github.com/psf/requests" in text
    assert "Metadata completeness delta: +0.35" in text
    assert "Author email domain age: 4 days" in text


def test_build_document_includes_all_typosquat_fields(tmp_path: Path):
    doc = build_document(_pkg(tmp_path, typosquat=_enriched_typosquat()))
    ts = doc["typosquat"]
    assert ts["confidence"] == 0.6
    assert ts["adjusted_confidence"] == 0.85
    assert ts["description_similarity"] == 0.72
    assert ts["classifier_overlap"] == 0.4
    assert ts["shared_repo_url"] == "https://github.com/psf/requests"
    assert ts["completeness_delta"] == 0.35
    assert ts["author_domain_age_days"] == 4


def test_build_document_typosquat_none_when_no_finding(tmp_path: Path):
    doc = build_document(_pkg(tmp_path))
    assert doc["typosquat"] is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_output_writer.py -v`
Expected: FAIL on the 4 new tests — the extra breakdown lines and dict keys don't exist yet.

- [ ] **Step 3: Implement**

In `nidhogg/output/writer.py`, replace the typosquat block in `format_results` (originally lines 234-242):

```python
    if analysis.typosquat is not None:
        ts = analysis.typosquat
        lines.append("")
        lines.append(_c("Typosquatting:", _BOLD, use_color=color))
        lines.append(
            f"  {_c('[TYPOSQUATTING]', _BOLD + _RED, use_color=color)}"
            f"  similar to {_c(ts.similar_to, _BOLD, use_color=color)}"
            f"  (distance={ts.distance}, method={ts.method.value})"
        )
        if ts.adjusted_confidence is not None:
            lines.append(
                f"    Confidence: {ts.confidence:.2f} -> {ts.adjusted_confidence:.2f} (adjusted)"
            )
        else:
            lines.append(f"    Confidence: {ts.confidence:.2f}")
        if ts.description_similarity is not None:
            lines.append(f"    Description similarity: {ts.description_similarity:.2f}")
        if ts.classifier_overlap is not None:
            lines.append(f"    Keyword/classifier overlap: {ts.classifier_overlap:.2f}")
        if ts.shared_repo_url is not None:
            lines.append(f"    Shared repo: {ts.shared_repo_url}")
        if ts.completeness_delta is not None:
            lines.append(f"    Metadata completeness delta: {ts.completeness_delta:+.2f}")
        if ts.author_domain_age_days is not None:
            lines.append(f"    Author email domain age: {ts.author_domain_age_days} days")
```

Replace the `"typosquat"` entry in `build_document` (originally lines 274-283):

```python
        "typosquat": (
            {
                "package_name": analysis.typosquat.package_name,
                "similar_to": analysis.typosquat.similar_to,
                "distance": analysis.typosquat.distance,
                "method": analysis.typosquat.method.value,
                "confidence": analysis.typosquat.confidence,
                "adjusted_confidence": analysis.typosquat.adjusted_confidence,
                "description_similarity": analysis.typosquat.description_similarity,
                "classifier_overlap": analysis.typosquat.classifier_overlap,
                "shared_repo_url": analysis.typosquat.shared_repo_url,
                "completeness_delta": analysis.typosquat.completeness_delta,
                "author_domain_age_days": analysis.typosquat.author_domain_age_days,
            }
            if analysis.typosquat is not None
            else None
        ),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_output_writer.py -v`
Expected: PASS, all tests (existing + 4 new).

Run: `uv run pytest tests/ -v`
Expected: full suite PASS.

Run: `uv run ruff check nidhogg/output/writer.py && uv run mypy nidhogg/output/writer.py`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/output/writer.py tests/test_output_writer.py
git commit -m "feat(output): show full typosquat signal breakdown in text and JSON output"
```

---

### Task 5: CLI — `--history-dir` flag and cache staleness warning

**Files:**
- Modify: `nidhogg/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `append_finding` (Task 1), `top_packages_last_updated` (Task 2), `TyposquatConfig.cache_max_age_days` (Task 3).
- Produces: `--history-dir PATH` flag (`args.history_dir`); `_warn_if_top_packages_stale() -> None`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_cli.py`:

```python
from datetime import UTC, datetime, timedelta

from nidhogg import cli
from nidhogg.cli import _run_analyze


def test_build_parser_history_dir_defaults_none():
    parser = _build_parser()
    args = parser.parse_args(["some/path"])
    assert args.history_dir is None


def test_build_parser_history_dir_accepts_path():
    parser = _build_parser()
    args = parser.parse_args(["some/path", "--history-dir", "/tmp/hist"])
    assert str(args.history_dir) == "/tmp/hist"


def test_run_analyze_appends_to_history(tmp_path: Path):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    history_dir = tmp_path / "history"
    exit_code = _run_analyze(
        pkg_dir,
        None,
        as_json=False,
        verbose=False,
        history_dir=history_dir,
    )
    assert exit_code == 0
    assert len(list(history_dir.glob("*.jsonl"))) == 1


def test_run_analyze_no_history_dir_writes_nothing(tmp_path: Path):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    exit_code = _run_analyze(pkg_dir, None, as_json=False, verbose=False)
    assert exit_code == 0
    # No history_dir was given, so nothing outside pkg_dir/output should exist.
    assert list(tmp_path.glob("*.jsonl")) == []


def test_warn_if_top_packages_stale_prints_when_old(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setattr(
        "nidhogg.analysis.typosquat.top_packages_last_updated",
        lambda: datetime.now(UTC) - timedelta(days=999),
    )
    cli._warn_if_top_packages_stale()
    assert "top-packages cache is" in capsys.readouterr().err


def test_warn_if_top_packages_stale_silent_when_fresh(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setattr(
        "nidhogg.analysis.typosquat.top_packages_last_updated",
        lambda: datetime.now(UTC),
    )
    cli._warn_if_top_packages_stale()
    assert capsys.readouterr().err == ""


def test_warn_if_top_packages_stale_silent_when_legacy_format(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setattr(
        "nidhogg.analysis.typosquat.top_packages_last_updated", lambda: None
    )
    cli._warn_if_top_packages_stale()
    assert capsys.readouterr().err == ""
```

Add `import pytest` to the top of `tests/test_cli.py` if not already present from Task 7 of the typosquat-metadata-signals plan (it isn't — that file only imports `Path` and `patch`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cli.py -v`
Expected: FAIL — `args.history_dir` doesn't exist (`AttributeError`), `_run_analyze` doesn't accept `history_dir` (`TypeError`), and `cli._warn_if_top_packages_stale` doesn't exist (`AttributeError`).

- [ ] **Step 3: Implement**

In `nidhogg/cli.py`, add the new argument in `_build_parser` (after `--no-typosquat-intel`, before `return parser`):

```python
    parser.add_argument(
        "--history-dir",
        type=Path,
        default=None,
        metavar="PATH",
        dest="history_dir",
        help="Append each result as JSONL to <PATH>/YYYY-MM-DD.jsonl.",
    )
    return parser
```

Add `history_dir: Path | None = None` to `_run_analyze`'s signature and docstring Args, and append the history write right after `analysis, verdict = result`:

```python
def _run_analyze(  # noqa: PLR0913
    package_path: Path,
    output: Path | None,
    *,
    as_json: bool,
    verbose: bool,
    benign_domains_path: Path | None = None,
    check_ssl: bool = False,
    package_name: str | None = None,
    typosquat_intel: bool = True,
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
            and raise confidence for Let's Encrypt issuers.
        package_name: When provided, run the typosquatting check with this name.
        typosquat_intel: When ``True`` (default), enrich typosquat matches with
            live PyPI/RDAP metadata.
        history_dir: When provided, append the result document as JSONL under
            this directory.

    Returns:
        ``0`` for a clean package, ``1`` for suspicious/malicious, ``2`` on error.
    """
    if not verbose:
        logger.remove()

    result = _analyse_one(
        package_path,
        benign_domains_path=benign_domains_path,
        check_ssl=check_ssl,
        package_name=package_name,
        typosquat_intel=typosquat_intel,
    )
    if result is None:
        return _EXIT_ERROR

    analysis, verdict = result

    if history_dir is not None:
        from nidhogg.output.history import append_finding  # noqa: PLC0415

        append_finding(history_dir, build_document(analysis))

    if output is not None:
        write_results(analysis, output)
    elif as_json:
        print(json.dumps(build_document(analysis), indent=2))  # noqa: T201
    else:
        use_color = sys.stdout.isatty()
        print(format_results(analysis, color=use_color))  # noqa: T201

    return 0 if verdict is Verdict.CLEAN else 1
```

Update `_run_batch`'s signature and docstring:

```python
def _run_batch(  # noqa: PLR0913
    packages_dir: Path,
    output: Path | None,
    *,
    as_json: bool,
    verbose: bool,
    benign_domains_path: Path | None = None,
    check_ssl: bool = False,
    typosquat_intel: bool = True,
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
            and raise confidence for Let's Encrypt issuers.
        typosquat_intel: When ``True`` (default), enrich typosquat matches with
            live PyPI/RDAP metadata.
        history_dir: When provided, append each package's result document as
            JSONL under this directory.

    Returns:
        ``0`` if all packages are clean, ``1`` if any is suspicious/malicious,
        ``2`` if any package could not be read.
    """
```

(This adds `typosquat_intel` and `history_dir` to the existing signature/docstring — `typosquat_intel` was already threaded through `_analyse_one` calls inside this function by the typosquat-metadata-signals plan; only `history_dir` is new here.)

Then write history inside the loop, right after `batch_results.append((analysis, _risk_level(analysis)))`:

```python
        batch_results.append((analysis, _risk_level(analysis)))

        if history_dir is not None:
            from nidhogg.output.history import append_finding  # noqa: PLC0415

            append_finding(history_dir, build_document(analysis))

        if output is not None or as_json:
```

(The `if output is not None or as_json:` line already exists immediately after — this only inserts the history block before it.)

Add a module-level function, placed just above `main()`:

```python
def _warn_if_top_packages_stale() -> None:
    """Print a non-blocking warning to stderr if the top-packages cache is stale."""
    from datetime import UTC, datetime  # noqa: PLC0415

    from nidhogg.analysis.typosquat import top_packages_last_updated  # noqa: PLC0415
    from nidhogg.typosquat_config import load_typosquat_config  # noqa: PLC0415

    last_updated = top_packages_last_updated()
    if last_updated is None:
        return
    age_days = (datetime.now(UTC) - last_updated).days
    max_age = load_typosquat_config().cache_max_age_days
    if age_days > max_age:
        print(  # noqa: T201
            f"Warning: top-packages cache is {age_days} days old. "
            "Consider running with --update-top-packages.",
            file=sys.stderr,
        )
```

In `main()`, call it right after `args = parser.parse_args()`, and forward `history_dir` in both dispatch branches:

```python
def main() -> None:
    """Entry point for the ``nidhogg`` CLI."""
    parser = _build_parser()
    args = parser.parse_args()
    _warn_if_top_packages_stale()
    package_path: Path = args.package_path
    output: Path | None = args.output
    as_json: bool = args.json
    verbose: bool = args.verbose
    benign_domains: Path | None = args.benign_domains
    check_ssl: bool = args.check_ssl
    batch: bool = args.batch
    update_top: bool = args.update_top_packages
    typosquat_intel: bool = args.typosquat_intel
    history_dir: Path | None = args.history_dir

    if update_top:
        from nidhogg.analysis.typosquat import update_top_packages  # noqa: PLC0415

        update_top_packages()

    if batch:
        sys.exit(
            _run_batch(
                package_path,
                output,
                as_json=as_json,
                verbose=verbose,
                benign_domains_path=benign_domains,
                check_ssl=check_ssl,
                typosquat_intel=typosquat_intel,
                history_dir=history_dir,
            )
        )
    else:
        sys.exit(
            _run_analyze(
                package_path,
                output,
                as_json=as_json,
                verbose=verbose,
                benign_domains_path=benign_domains,
                check_ssl=check_ssl,
                package_name=_infer_package_name(package_path),
                typosquat_intel=typosquat_intel,
                history_dir=history_dir,
            )
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli.py -v`
Expected: PASS, all tests (4 from the typosquat-metadata-signals plan + 7 new = 11).

Run: `uv run pytest tests/ -v`
Expected: full suite PASS.

Run: `uv run ruff check nidhogg/cli.py && uv run mypy nidhogg/cli.py`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/cli.py tests/test_cli.py
git commit -m "feat(cli): add --history-dir flag and top-packages staleness warning"
```

---

## Final Verification

- [ ] Run the complete suite once more: `uv run pytest tests/ -v`
- [ ] Run `uv run ruff check .` and `uv run ruff format --check .`
- [ ] Run `uv run mypy nidhogg/`
- [ ] Manually smoke-test: `uv run nidhogg <any extracted package dir> --history-dir /tmp/nidhogg-history` creates a dated JSONL file; running it again the same day appends a second line to the same file.
