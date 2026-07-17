# Typosquat Metadata Signals Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a configurable pluralization detector, a base/adjusted confidence score, and live PyPI+RDAP metadata signals to Nidhogg's typosquat detector, wired into the CLI and the global scoring formula.

**Architecture:** `analysis/typosquat.py` gains a config-driven confidence + known-exceptions layer and one new detector (`pluralization`). A new `enrichment/pypi_metadata.py` module fetches PyPI JSON API + RDAP data (stdlib `urllib.request` only) and computes a bounded confidence boost, applied on top of the base confidence to produce `adjusted_confidence`. `cli.py` and `scoring.py` consume the new fields.

**Tech Stack:** Python 3.14, stdlib only (`urllib.request`, `tomllib`, `functools`, `dataclasses`), pytest, `unittest.mock.patch` for network mocking (no `responses`/`httpx` — matches existing `ssl_cert.py` convention).

## Global Constraints

- No new dependencies — network calls use `urllib.request` (see `nidhogg/enrichment/ssl_cert.py` and `nidhogg/analysis/typosquat.py::update_top_packages` for the existing pattern).
- Mypy strict: every function has full type hints including return types (see `pyproject.toml` `[tool.mypy]`).
- Docstrings: Google style, on every public function (ruff `pydocstyle convention = "google"`).
- Run `uv run pytest`, `uv run ruff check`, `uv run ruff format --check`, and `uv run mypy` before each commit that finishes a task.
- Config values live in TOML under `nidhogg/data/`, loaded via a `functools.cache`d loader that mirrors `nidhogg/scoring.py::load_scoring_config`.
- Network-touching functions are tested by mocking the lowest-level fetch function with `unittest.mock.patch`, never a live network call (see `tests/test_ssl_cert.py`).

---

### Task 1: Extend `TyposquatFinding` and `TyposquatMethod`

**Files:**
- Modify: `nidhogg/core/models.py:108-131`
- Test: `tests/test_models.py`

**Interfaces:**
- Produces: `TyposquatMethod.PLURALIZATION`; `TyposquatFinding.confidence: float = 0.0`, `.adjusted_confidence: float | None = None`, `.description_similarity: float | None = None`, `.classifier_overlap: float | None = None`, `.shared_repo_url: str | None = None`, `.completeness_delta: float | None = None`, `.author_domain_age_days: int | None = None`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_models.py` (after the exceptions section, or anywhere at module level):

```python
from nidhogg.core.models import TyposquatFinding, TyposquatMethod


def test_typosquat_method_pluralization_value():
    assert TyposquatMethod.PLURALIZATION.value == "pluralization"


def test_typosquat_finding_new_fields_default_to_none():
    finding = TyposquatFinding(
        package_name="databas",
        similar_to="databases",
        distance=2,
        method=TyposquatMethod.PLURALIZATION,
    )
    assert finding.confidence == 0.0
    assert finding.adjusted_confidence is None
    assert finding.description_similarity is None
    assert finding.classifier_overlap is None
    assert finding.shared_repo_url is None
    assert finding.completeness_delta is None
    assert finding.author_domain_age_days is None


def test_typosquat_finding_accepts_all_fields():
    finding = TyposquatFinding(
        package_name="databas",
        similar_to="databases",
        distance=2,
        method=TyposquatMethod.PLURALIZATION,
        confidence=0.4,
        adjusted_confidence=0.6,
        description_similarity=0.7,
        classifier_overlap=0.5,
        shared_repo_url="https://github.com/x/y",
        completeness_delta=0.2,
        author_domain_age_days=3,
    )
    assert finding.confidence == 0.4
    assert finding.adjusted_confidence == 0.6
    assert finding.shared_repo_url == "https://github.com/x/y"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_models.py -k typosquat_finding_new_fields -v`
Expected: FAIL with `TypeError: TyposquatFinding.__init__() got an unexpected keyword argument` or `AttributeError` (the fields don't exist yet).

- [ ] **Step 3: Implement**

In `nidhogg/core/models.py`, replace lines 108-131:

```python
class TyposquatMethod(enum.Enum):
    """Technique used to match a package name to a popular package."""

    LEVENSHTEIN = "levenshtein"
    TRANSPOSITION = "transposition"
    SUBSTITUTION = "substitution"
    AFFIX = "affix"
    PLURALIZATION = "pluralization"


@dataclass
class TyposquatFinding:
    """A suspected typosquatting similarity to a popular package.

    Attributes:
        package_name: The name of the analysed package.
        similar_to: The popular package it resembles.
        distance: Edit distance between the two normalised names.
        method: Detection technique that found the similarity.
        confidence: Base confidence assigned by ``check_typosquatting``
            according to the detection method. ``0.0`` until assigned.
        adjusted_confidence: Confidence after applying the PyPI/RDAP
            metadata boost from ``enrich_typosquat``. ``None`` when
            enrichment has not run (or failed).
        description_similarity: Cosine similarity between the candidate's
            and target's PyPI summaries. ``None`` when not enriched.
        classifier_overlap: Jaccard overlap between keywords + PyPI
            classifiers of the candidate and target. ``None`` when not
            enriched.
        shared_repo_url: A project/home page URL shared between candidate
            and target, if any. ``None`` when not enriched or not found.
        completeness_delta: Difference in metadata completeness between
            target and candidate. ``None`` when not enriched.
        author_domain_age_days: Age in days of the candidate author's email
            domain registration relative to the candidate's first release.
            Negative when the domain was registered after the release.
            ``None`` when not enriched or unavailable.
    """

    package_name: str
    similar_to: str
    distance: int
    method: TyposquatMethod
    confidence: float = 0.0
    adjusted_confidence: float | None = None
    description_similarity: float | None = None
    classifier_overlap: float | None = None
    shared_repo_url: str | None = None
    completeness_delta: float | None = None
    author_domain_age_days: int | None = None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_models.py -v`
Expected: PASS, all tests including the 3 new ones.

- [ ] **Step 5: Full test suite + lint sanity check**

Run: `uv run pytest tests/ -v`
Expected: PASS (existing `TyposquatFinding(...)` construction sites in `nidhogg/analysis/typosquat.py` and `tests/test_scoring.py` still work — the new fields all have defaults).

Run: `uv run ruff check nidhogg/core/models.py` and `uv run mypy nidhogg/core/models.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add nidhogg/core/models.py tests/test_models.py
git commit -m "feat(models): add confidence and metadata fields to TyposquatFinding"
```

---

### Task 2: `typosquat.toml` config + loader

**Files:**
- Create: `nidhogg/data/typosquat.toml`
- Create: `nidhogg/typosquat_config.py`
- Test: `tests/test_typosquat_config.py`

**Interfaces:**
- Consumes: `nidhogg.core.models.TyposquatMethod` (Task 1).
- Produces: `nidhogg.typosquat_config.TyposquatConfig` (frozen dataclass with `max_distance: int`, `confidence: dict[TyposquatMethod, float]`, `known_exceptions: frozenset[tuple[str, str]]`), `nidhogg.typosquat_config.load_typosquat_config(path: Path | None = None) -> TyposquatConfig`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_typosquat_config.py`:

```python
"""Tests for typosquat_config.py."""

from __future__ import annotations

from pathlib import Path

from nidhogg.core.models import TyposquatMethod
from nidhogg.typosquat_config import load_typosquat_config


def test_load_typosquat_config_default_max_distance():
    cfg = load_typosquat_config()
    assert cfg.max_distance == 1


def test_load_typosquat_config_has_confidence_for_every_method():
    cfg = load_typosquat_config()
    for method in TyposquatMethod:
        assert method in cfg.confidence
        assert 0.0 <= cfg.confidence[method] <= 1.0


def test_load_typosquat_config_default_known_exceptions_empty():
    cfg = load_typosquat_config()
    assert cfg.known_exceptions == frozenset()


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
""",
        encoding="utf-8",
    )
    cfg = load_typosquat_config(custom)
    assert cfg.max_distance == 2
    assert ("request", "requests") in cfg.known_exceptions
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_typosquat_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'nidhogg.typosquat_config'`.

- [ ] **Step 3: Implement**

Create `nidhogg/data/typosquat.toml`:

```toml
# Typosquat detection thresholds and confidence weights.
# Edit this file to tune sensitivity without touching Python code.

# Pairs [candidate, target] that are never reported even if they match.
known_exceptions = [
]

[levenshtein]
# Maximum edit distance to consider a name a typosquat.
max_distance = 1

[confidence]
# Base confidence assigned to a finding, indexed by detection method.
levenshtein = 0.6
transposition = 0.55
substitution = 0.55
affix = 0.35
pluralization = 0.4
```

Create `nidhogg/typosquat_config.py`:

```python
"""Typosquat detection configuration: thresholds and exceptions from typosquat.toml."""

from __future__ import annotations

import functools
import tomllib
from dataclasses import dataclass
from importlib.resources import files
from typing import TYPE_CHECKING, Any

from nidhogg.core.models import TyposquatMethod

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class TyposquatConfig:
    """Complete typosquat configuration loaded from typosquat.toml.

    Attributes:
        max_distance: Maximum Levenshtein distance to consider a name a
            typosquat of a top package.
        confidence: Base confidence value for each detection method.
        known_exceptions: Pairs of ``(candidate, target)`` normalised names
            that are never reported even if they match.
    """

    max_distance: int
    confidence: dict[TyposquatMethod, float]
    known_exceptions: frozenset[tuple[str, str]]


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

    confidence = {
        TyposquatMethod(name): float(value) for name, value in confidence_raw.items()
    }
    known_exceptions = frozenset(
        (pair[0], pair[1]) for pair in exceptions_raw
    )

    return TyposquatConfig(
        max_distance=int(levenshtein["max_distance"]),
        confidence=confidence,
        known_exceptions=known_exceptions,
    )


@functools.cache
def load_typosquat_config(path: Path | None = None) -> TyposquatConfig:
    """Load and return the typosquat configuration, caching the result.

    Args:
        path: Path to a custom ``typosquat.toml``. When ``None``, the file
            bundled with the package (``nidhogg/data/typosquat.toml``) is
            used.

    Returns:
        A fully populated :class:`TyposquatConfig`.
    """
    if path is None:
        raw: bytes = (
            files("nidhogg").joinpath("data").joinpath("typosquat.toml").read_bytes()
        )
        data = tomllib.loads(raw.decode())
    else:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    return _parse_config(data)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_typosquat_config.py -v`
Expected: PASS, all 4 tests.

Run: `uv run ruff check nidhogg/typosquat_config.py nidhogg/data/typosquat.toml` and `uv run mypy nidhogg/typosquat_config.py`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/data/typosquat.toml nidhogg/typosquat_config.py tests/test_typosquat_config.py
git commit -m "feat(typosquat): add typosquat.toml config and loader"
```

---

### Task 3: Wire config into `check_typosquatting` + add `pluralization` detector

**Files:**
- Modify: `nidhogg/analysis/typosquat.py`
- Test: `tests/test_typosquat.py`

**Interfaces:**
- Consumes: `nidhogg.typosquat_config.load_typosquat_config` (Task 2), `TyposquatMethod.PLURALIZATION` (Task 1).
- Produces: `check_typosquatting` now sets `finding.confidence`, filters `known_exceptions`, and detects pluralized names; `_check_pluralization(normalised: str, top: frozenset[str]) -> TyposquatFinding | None`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_typosquat.py`:

```python
from nidhogg.typosquat_config import load_typosquat_config


def test_typosquat_pluralizacion_es_detectada() -> None:
    """A name missing the 'es' suffix of a real package is flagged as PLURALIZATION."""
    # 'databas' is distance 2 from 'databases' (missing 'es'); Levenshtein-1
    # (the default max_distance) does not catch it, so PLURALIZATION must.
    finding = check_typosquatting("databas")
    assert finding is not None
    assert finding.similar_to == "databases"
    assert finding.method == TyposquatMethod.PLURALIZATION


def test_typosquat_confidence_asignada_segun_metodo() -> None:
    """The base confidence matches the configured value for the method used."""
    cfg = load_typosquat_config()
    finding = check_typosquatting("rquests")
    assert finding is not None
    assert finding.confidence == pytest.approx(cfg.confidence[TyposquatMethod.LEVENSHTEIN])


def test_typosquat_known_exception_no_se_reporta(monkeypatch: pytest.MonkeyPatch) -> None:
    """A (candidate, target) pair listed in known_exceptions is never reported."""
    cfg = load_typosquat_config()
    patched = dataclasses.replace(
        cfg, known_exceptions=frozenset({("rquests", "requests")})
    )
    monkeypatch.setattr(
        "nidhogg.analysis.typosquat.load_typosquat_config", lambda: patched
    )
    assert check_typosquatting("rquests") is None


def test_typosquat_max_distance_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raising max_distance detects names that the default threshold misses."""
    cfg = load_typosquat_config()
    patched = dataclasses.replace(cfg, max_distance=2)
    monkeypatch.setattr(
        "nidhogg.analysis.typosquat.load_typosquat_config", lambda: patched
    )
    # 'rezquesta' is distance 2 from 'requests' (inserted 'z', 's'->'a'); at
    # the default max_distance=1 this is not found by any check
    # (verified: check_typosquatting("rezquesta") is None). Confirm the
    # configured threshold is actually used.
    finding = check_typosquatting("rezquesta")
    assert finding is not None
    assert finding.similar_to == "requests"
    assert finding.method == TyposquatMethod.LEVENSHTEIN
```

Add the needed imports at the top of `tests/test_typosquat.py`:

```python
import dataclasses

import pytest

from nidhogg.analysis.typosquat import check_typosquatting
from nidhogg.core.models import TyposquatMethod
```

(`dataclasses` and `pytest` are new imports; `check_typosquatting`/`TyposquatMethod` already exist in the file.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_typosquat.py -k "pluralizacion or confidence_asignada or known_exception or max_distance_configurable" -v`
Expected: FAIL — `test_typosquat_pluralizacion_es_detectada` fails because `_check_pluralization` doesn't exist yet (finding is `None`); `test_typosquat_confidence_asignada_segun_metodo` fails because `finding.confidence == 0.0`, not the configured value; the `known_exception`/`max_distance` tests fail with `AttributeError` (`load_typosquat_config` not imported/used in `typosquat.py` yet).

- [ ] **Step 3: Implement**

In `nidhogg/analysis/typosquat.py`, add the import and remove the now-unused constant:

```python
from nidhogg.core.models import TyposquatFinding, TyposquatMethod
from nidhogg.typosquat_config import load_typosquat_config

# Maximum edit distance to consider a name a typosquat.
_MAX_TRANSPOSITION = 2
```

(Delete the line `_MAX_LEVENSHTEIN = 1` — it's replaced by `cfg.max_distance`.)

Change `_check_levenshtein`'s signature and body (currently lines 105-124):

```python
def _check_levenshtein(
    normalised: str, top: list[str], *, max_distance: int
) -> TyposquatFinding | None:
    """Check if *normalised* is within *max_distance* of any top package.

    Args:
        normalised: Normalised name of the package under analysis.
        top: Sorted list of normalised top package names.
        max_distance: Maximum edit distance to consider a match.

    Returns:
        A :class:`TyposquatFinding` if a match is found, else ``None``.
    """
    for candidate in top:
        dist = _levenshtein(normalised, candidate)
        if dist <= max_distance:
            return TyposquatFinding(
                package_name=normalised,
                similar_to=candidate,
                distance=dist,
                method=TyposquatMethod.LEVENSHTEIN,
            )
    return None
```

Add the new generator after `_check_affix` (before `check_typosquatting`):

```python
# Suffixes tried when checking for singular/plural variants.
_PLURAL_SUFFIXES = ("s", "es")


def _check_pluralization(
    normalised: str, top: frozenset[str]
) -> TyposquatFinding | None:
    """Check singular/plural variants (e.g. ``box`` → ``boxes``).

    Tries both adding and removing each suffix in ``_PLURAL_SUFFIXES``.

    Args:
        normalised: Normalised name under analysis.
        top: Set of normalised top package names.

    Returns:
        A :class:`TyposquatFinding` if a match is found, else ``None``.
    """
    for suffix in _PLURAL_SUFFIXES:
        candidate = normalised[: -len(suffix)] if normalised.endswith(suffix) else normalised + suffix
        if candidate != normalised and candidate in top:
            return TyposquatFinding(
                package_name=normalised,
                similar_to=candidate,
                distance=_levenshtein(normalised, candidate),
                method=TyposquatMethod.PLURALIZATION,
            )
    return None
```

Replace `check_typosquatting` (currently lines 209-249):

```python
def check_typosquatting(package_name: str) -> TyposquatFinding | None:
    """Check whether *package_name* looks like a typosquat of a popular package.

    The check is skipped (returns ``None``) when the name itself is already
    in the top-5000 list, or when the matched ``(candidate, target)`` pair is
    listed in ``typosquat.toml``'s ``known_exceptions``.

    Detection strategies (in order):
    1. Levenshtein distance ≤ ``typosquat.toml``'s ``max_distance``.
    2. Single adjacent transposition.
    3. Common visual substitutions (``1→l``, ``0→o``, etc.).
    4. Typical affixes (``-dev``, ``py-``, etc.).
    5. Singular/plural suffix variants (``s``/``es``).

    Args:
        package_name: Name of the package to check (raw, not yet normalised).

    Returns:
        A :class:`TyposquatFinding` if a suspicious similarity is detected,
        or ``None`` when the package appears legitimate.
    """
    normalised = _normalise(package_name)
    top_set = _load_top_packages()

    # The package itself is in the top list → it is the real thing.
    if normalised in top_set:
        return None

    cfg = load_typosquat_config()
    top_list = _load_top_packages_list()

    finding = (
        _check_levenshtein(normalised, top_list, max_distance=cfg.max_distance)
        or _check_transposition(normalised, top_set)
        or _check_substitution(normalised, top_set)
        or _check_affix(normalised, top_set)
        or _check_pluralization(normalised, top_set)
    )
    if finding is None:
        return None

    if (finding.package_name, finding.similar_to) in cfg.known_exceptions:
        return None

    finding.confidence = cfg.confidence[finding.method]
    return finding
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_typosquat.py -v`
Expected: PASS, all tests (existing 9 + 4 new = 13).

- [ ] **Step 5: Full suite + lint**

Run: `uv run pytest tests/ -v && uv run ruff check nidhogg/analysis/typosquat.py && uv run mypy nidhogg/analysis/typosquat.py`
Expected: all PASS, no lint/type errors. (`tests/test_scoring.py`'s two direct `TyposquatFinding(...)` constructions still work — they don't go through `check_typosquatting`, so `confidence` stays at its `0.0` default there, which those tests don't check.)

- [ ] **Step 6: Commit**

```bash
git add nidhogg/analysis/typosquat.py tests/test_typosquat.py
git commit -m "feat(typosquat): use typosquat.toml for threshold/confidence/exceptions, add pluralization detector"
```

---

### Task 4: `enrichment/pypi_metadata.py` — data models + fetch functions

**Files:**
- Create: `nidhogg/enrichment/pypi_metadata.py`
- Test: `tests/test_pypi_metadata.py`

**Interfaces:**
- Produces: `PackageMetadata` (frozen dataclass), `DomainInfo` (frozen dataclass), `fetch_package_metadata(name: str) -> PackageMetadata | None`, `fetch_domain_info(domain: str) -> DomainInfo | None`, `extract_email_domain(email: str | None) -> str | None`.
- Internal (mocked in tests): `_fetch_pypi_json(name: str) -> dict[str, object]`, `_fetch_rdap_json(domain: str) -> dict[str, object]`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_pypi_metadata.py`:

```python
"""Tests for enrichment/pypi_metadata.py."""

from __future__ import annotations

from unittest.mock import patch

from nidhogg.enrichment.pypi_metadata import (
    extract_email_domain,
    fetch_domain_info,
    fetch_package_metadata,
)

_PYPI_PAYLOAD = {
    "info": {
        "author_email": "dev@example.com",
        "maintainer_email": None,
        "summary": "A tiny test package",
        "keywords": "http, requests",
        "classifiers": ["Topic :: Internet"],
        "project_urls": {"Homepage": "https://github.com/x/testpkg-a"},
        "home_page": None,
    },
    "releases": {
        "1.0.0": [{"upload_time_iso_8601": "2024-01-01T00:00:00.000000Z"}],
        "1.1.0": [{"upload_time_iso_8601": "2024-06-01T00:00:00.000000Z"}],
    },
}

_RDAP_PAYLOAD = {
    "ldhName": "example.com",
    "events": [
        {"eventAction": "registration", "eventDate": "2024-01-01T00:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2024-06-01T00:00:00Z"},
    ],
}


def test_extract_email_domain_valid():
    assert extract_email_domain("dev@Example.com") == "example.com"


def test_extract_email_domain_none():
    assert extract_email_domain(None) is None


def test_extract_email_domain_malformed():
    assert extract_email_domain("not-an-email") is None


def test_fetch_package_metadata_parses_payload():
    with patch(
        "nidhogg.enrichment.pypi_metadata._fetch_pypi_json",
        return_value=_PYPI_PAYLOAD,
    ):
        meta = fetch_package_metadata("testpkg-fetch-a")
    assert meta is not None
    assert meta.author_email == "dev@example.com"
    assert meta.summary == "A tiny test package"
    assert meta.keywords == ("http", "requests")
    assert meta.classifiers == ("Topic :: Internet",)
    assert meta.home_page is None
    assert meta.project_urls == (("Homepage", "https://github.com/x/testpkg-a"),)
    assert meta.first_release_at is not None
    assert meta.first_release_at.year == 2024
    assert meta.first_release_at.month == 1


def test_fetch_package_metadata_returns_none_on_network_error():
    import urllib.error

    with patch(
        "nidhogg.enrichment.pypi_metadata._fetch_pypi_json",
        side_effect=urllib.error.URLError("boom"),
    ):
        assert fetch_package_metadata("testpkg-fetch-b") is None


def test_fetch_domain_info_parses_registration_date():
    with patch(
        "nidhogg.enrichment.pypi_metadata._fetch_rdap_json",
        return_value=_RDAP_PAYLOAD,
    ):
        info = fetch_domain_info("example-fetch-a.com")
    assert info is not None
    assert info.registered_at is not None
    assert info.registered_at.year == 2024
    assert info.registered_at.month == 1


def test_fetch_domain_info_returns_none_on_network_error():
    import urllib.error

    with patch(
        "nidhogg.enrichment.pypi_metadata._fetch_rdap_json",
        side_effect=urllib.error.URLError("boom"),
    ):
        assert fetch_domain_info("example-fetch-b.com") is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_pypi_metadata.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'nidhogg.enrichment.pypi_metadata'`.

- [ ] **Step 3: Implement**

Create `nidhogg/enrichment/pypi_metadata.py`:

```python
"""PyPI + RDAP metadata fetching for typosquat enrichment.

Fetches live PyPI JSON API metadata and RDAP domain registration data.
Network calls are best-effort: any failure is logged at debug level and
the caller receives ``None`` instead of an exception.
"""

from __future__ import annotations

import functools
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from loguru import logger

_PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"
_RDAP_URL = "https://rdap.org/domain/{domain}"
_REQUEST_TIMEOUT = 10.0


@dataclass(frozen=True)
class PackageMetadata:
    """Subset of PyPI JSON API metadata relevant to typosquat signals.

    Attributes:
        name: Package name as looked up.
        author_email: Author email from PyPI metadata, if set.
        maintainer_email: Maintainer email from PyPI metadata, if set.
        summary: One-line package summary.
        keywords: Comma-separated keywords, parsed into a tuple.
        classifiers: PyPI trove classifiers.
        project_urls: ``(label, url)`` pairs from ``project_urls``.
        home_page: The ``home_page`` metadata field, if set.
        first_release_at: Earliest upload timestamp across all releases.
    """

    name: str
    author_email: str | None
    maintainer_email: str | None
    summary: str | None
    keywords: tuple[str, ...]
    classifiers: tuple[str, ...]
    project_urls: tuple[tuple[str, str], ...]
    home_page: str | None
    first_release_at: datetime | None


@dataclass(frozen=True)
class DomainInfo:
    """Subset of RDAP domain data relevant to typosquat signals.

    Attributes:
        registered_at: Domain registration timestamp, if known.
    """

    registered_at: datetime | None


def _parse_keywords(raw: object) -> tuple[str, ...]:
    """Split a comma-separated keywords string into a tuple.

    Args:
        raw: The raw ``keywords`` field from PyPI metadata.

    Returns:
        A tuple of trimmed, non-empty keywords.
    """
    if not isinstance(raw, str) or not raw:
        return ()
    return tuple(kw.strip() for kw in raw.split(",") if kw.strip())


def _all_upload_dates(releases: dict[str, object]) -> list[datetime]:
    """Collect every upload timestamp across all releases.

    Args:
        releases: The raw ``releases`` mapping from a PyPI JSON payload.

    Returns:
        A list of parsed upload timestamps.
    """
    dates: list[datetime] = []
    for files in releases.values():
        if not isinstance(files, list):
            continue
        for file in files:
            raw = file.get("upload_time_iso_8601") if isinstance(file, dict) else None
            if isinstance(raw, str):
                dates.append(datetime.fromisoformat(raw.replace("Z", "+00:00")))
    return dates


def _fetch_pypi_json(name: str) -> dict[str, Any]:
    """Fetch the raw PyPI JSON API payload for *name*.

    Args:
        name: Package name (used verbatim in the URL).

    Returns:
        The parsed JSON document.

    Raises:
        urllib.error.URLError: On network failure or a non-2xx response.
        ValueError: If the response body is not valid JSON.
    """
    url = _PYPI_JSON_URL.format(name=name)
    with urllib.request.urlopen(url, timeout=_REQUEST_TIMEOUT) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))  # type: ignore[no-any-return]


def _fetch_rdap_json(domain: str) -> dict[str, Any]:
    """Fetch the raw RDAP payload for *domain*.

    Args:
        domain: Registrable domain name.

    Returns:
        The parsed JSON document.

    Raises:
        urllib.error.URLError: On network failure or a non-2xx response.
        ValueError: If the response body is not valid JSON.
    """
    url = _RDAP_URL.format(domain=domain)
    with urllib.request.urlopen(url, timeout=_REQUEST_TIMEOUT) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))  # type: ignore[no-any-return]


def _parse_package_metadata(name: str, payload: dict[str, Any]) -> PackageMetadata:
    """Convert a raw PyPI JSON payload into a :class:`PackageMetadata`.

    Args:
        name: Package name (echoed into the result).
        payload: Parsed PyPI JSON API document.

    Returns:
        The extracted :class:`PackageMetadata`.
    """
    info: dict[str, Any] = payload["info"]
    releases: dict[str, Any] = payload.get("releases", {})
    return PackageMetadata(
        name=name,
        author_email=info.get("author_email") or None,
        maintainer_email=info.get("maintainer_email") or None,
        summary=info.get("summary") or None,
        keywords=_parse_keywords(info.get("keywords")),
        classifiers=tuple(info.get("classifiers") or ()),
        project_urls=tuple((info.get("project_urls") or {}).items()),
        home_page=info.get("home_page") or None,
        first_release_at=min(_all_upload_dates(releases), default=None),
    )


def _parse_domain_info(payload: dict[str, Any]) -> DomainInfo:
    """Convert a raw RDAP payload into a :class:`DomainInfo`.

    Args:
        payload: Parsed RDAP JSON document.

    Returns:
        The extracted :class:`DomainInfo`.
    """
    registered_at: datetime | None = None
    for event in payload.get("events", []):
        if event.get("eventAction") == "registration":
            raw_date = event.get("eventDate")
            if isinstance(raw_date, str):
                registered_at = datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
    return DomainInfo(registered_at=registered_at)


@functools.cache
def fetch_package_metadata(name: str) -> PackageMetadata | None:
    """Fetch and cache PyPI metadata for *name*.

    Args:
        name: Package name to look up on PyPI.

    Returns:
        The parsed :class:`PackageMetadata`, or ``None`` if the lookup
        failed for any reason (package not found, network error, malformed
        response, ...).
    """
    try:
        payload = _fetch_pypi_json(name)
        return _parse_package_metadata(name, payload)
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as exc:
        logger.debug("PyPI metadata lookup failed for {!r}: {}", name, exc)
        return None


@functools.cache
def fetch_domain_info(domain: str) -> DomainInfo | None:
    """Fetch and cache RDAP registration data for *domain*.

    Args:
        domain: Registrable domain name to look up.

    Returns:
        The parsed :class:`DomainInfo`, or ``None`` if the lookup failed.
    """
    try:
        payload = _fetch_rdap_json(domain)
        return _parse_domain_info(payload)
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as exc:
        logger.debug("RDAP lookup failed for {!r}: {}", domain, exc)
        return None


def extract_email_domain(email: str | None) -> str | None:
    """Extract the lowercased domain part of an email address.

    Args:
        email: Raw email address, or ``None``.

    Returns:
        The lowercased domain, or ``None`` if *email* is empty or has no
        ``@``.
    """
    if not email or "@" not in email:
        return None
    return email.rsplit("@", 1)[-1].lower()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_pypi_metadata.py -v`
Expected: PASS, all 7 tests.

Run: `uv run ruff check nidhogg/enrichment/pypi_metadata.py && uv run mypy nidhogg/enrichment/pypi_metadata.py`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/enrichment/pypi_metadata.py tests/test_pypi_metadata.py
git commit -m "feat(enrichment): add PyPI + RDAP metadata fetchers"
```

---

### Task 5: Pure signal functions + `confidence_boost`

**Files:**
- Modify: `nidhogg/enrichment/pypi_metadata.py`
- Test: `tests/test_pypi_metadata.py`

**Interfaces:**
- Consumes: `PackageMetadata`, `DomainInfo` (Task 4).
- Produces: `description_similarity`, `keyword_classifier_overlap`, `shared_repo_url`, `metadata_completeness`, `completeness_delta`, `domain_age_days`, `confidence_boost` — all pure functions, no I/O.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_pypi_metadata.py`:

```python
from datetime import UTC, datetime

from nidhogg.enrichment.pypi_metadata import (
    DomainInfo,
    PackageMetadata,
    completeness_delta,
    confidence_boost,
    description_similarity,
    domain_age_days,
    keyword_classifier_overlap,
    metadata_completeness,
    shared_repo_url,
)


def _meta(**overrides: object) -> PackageMetadata:
    defaults: dict[str, object] = {
        "name": "pkg",
        "author_email": None,
        "maintainer_email": None,
        "summary": None,
        "keywords": (),
        "classifiers": (),
        "project_urls": (),
        "home_page": None,
        "first_release_at": None,
    }
    defaults.update(overrides)
    return PackageMetadata(**defaults)  # type: ignore[arg-type]


def test_description_similarity_identical_summaries():
    a = _meta(summary="fast http client for python")
    b = _meta(summary="fast http client for python")
    assert description_similarity(a, b) == 1.0


def test_description_similarity_missing_summary_is_zero():
    a = _meta(summary=None)
    b = _meta(summary="fast http client")
    assert description_similarity(a, b) == 0.0


def test_description_similarity_unrelated_summaries_low():
    a = _meta(summary="fast http client for python")
    b = _meta(summary="a video game about spaceships")
    assert description_similarity(a, b) < 0.2


def test_keyword_classifier_overlap_full_overlap():
    a = _meta(keywords=("http", "async"), classifiers=("Topic :: Internet",))
    b = _meta(keywords=("http", "async"), classifiers=("Topic :: Internet",))
    assert keyword_classifier_overlap(a, b) == 1.0


def test_keyword_classifier_overlap_no_overlap_is_zero():
    a = _meta(keywords=("http",))
    b = _meta(keywords=("gaming",))
    assert keyword_classifier_overlap(a, b) == 0.0


def test_shared_repo_url_matches_normalised_home_page():
    a = _meta(home_page="https://GitHub.com/x/pkg/")
    b = _meta(home_page="https://github.com/x/pkg")
    assert shared_repo_url(a, b) == "https://GitHub.com/x/pkg/"


def test_shared_repo_url_none_when_no_overlap():
    a = _meta(home_page="https://github.com/x/pkg-a")
    b = _meta(home_page="https://github.com/y/pkg-b")
    assert shared_repo_url(a, b) is None


def test_metadata_completeness_all_fields_present():
    meta = _meta(
        author_email="a@example.com",
        summary="x",
        home_page="https://example.com",
        classifiers=("Topic :: Internet",),
    )
    assert metadata_completeness(meta) == 1.0


def test_metadata_completeness_no_fields_is_zero():
    assert metadata_completeness(_meta()) == 0.0


def test_completeness_delta_positive_when_target_more_complete():
    sparse = _meta()
    rich = _meta(author_email="a@example.com", summary="x")
    assert completeness_delta(sparse, rich) > 0


def test_domain_age_days_negative_when_registered_after_release():
    info = DomainInfo(registered_at=datetime(2024, 6, 1, tzinfo=UTC))
    reference = datetime(2024, 1, 1, tzinfo=UTC)
    assert domain_age_days(info, reference) < 0


def test_domain_age_days_none_when_unregistered():
    info = DomainInfo(registered_at=None)
    assert domain_age_days(info, datetime(2024, 1, 1, tzinfo=UTC)) is None


def test_confidence_boost_no_signals_is_zero():
    boost = confidence_boost(
        description_similarity=None,
        classifier_overlap=None,
        shared_repo_url=None,
        completeness_delta=None,
        author_domain_age_days=None,
    )
    assert boost == 0.0


def test_confidence_boost_capped_at_0_35():
    boost = confidence_boost(
        description_similarity=0.9,
        classifier_overlap=0.9,
        shared_repo_url="https://example.com",
        completeness_delta=0.9,
        author_domain_age_days=-5,
    )
    assert boost == 0.35


def test_confidence_boost_shared_repo_adds_expected_amount():
    boost = confidence_boost(
        description_similarity=None,
        classifier_overlap=None,
        shared_repo_url="https://example.com",
        completeness_delta=None,
        author_domain_age_days=None,
    )
    assert boost == 0.25
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_pypi_metadata.py -v`
Expected: FAIL with `ImportError` (the new functions don't exist yet).

- [ ] **Step 3: Implement**

Append to `nidhogg/enrichment/pypi_metadata.py` (add `import re` and `from collections import Counter` and `from urllib.parse import urlsplit` to the top-of-file imports first):

```python
import re
from collections import Counter
from urllib.parse import urlsplit
```

Then append the functions:

```python
_WORD_RE = re.compile(r"\w+")
_MAX_BOOST = 0.35


def description_similarity(a: PackageMetadata, b: PackageMetadata) -> float:
    """Cosine similarity between the two packages' PyPI summaries.

    Args:
        a: Metadata of the first package.
        b: Metadata of the second package.

    Returns:
        A value in ``[0.0, 1.0]``; ``0.0`` if either summary is missing.
    """
    tokens_a = Counter(_WORD_RE.findall(a.summary.lower())) if a.summary else Counter()
    tokens_b = Counter(_WORD_RE.findall(b.summary.lower())) if b.summary else Counter()
    if not tokens_a or not tokens_b:
        return 0.0
    dot = sum(count * tokens_b[word] for word, count in tokens_a.items())
    norm_a = sum(count * count for count in tokens_a.values()) ** 0.5
    norm_b = sum(count * count for count in tokens_b.values()) ** 0.5
    return round(dot / (norm_a * norm_b), 4)


def keyword_classifier_overlap(a: PackageMetadata, b: PackageMetadata) -> float:
    """Jaccard overlap between the two packages' keywords + PyPI classifiers.

    Args:
        a: Metadata of the first package.
        b: Metadata of the second package.

    Returns:
        A value in ``[0.0, 1.0]``; ``0.0`` if either set is empty.
    """
    set_a = {kw.lower() for kw in (*a.keywords, *a.classifiers)}
    set_b = {kw.lower() for kw in (*b.keywords, *b.classifiers)}
    if not set_a or not set_b:
        return 0.0
    return round(len(set_a & set_b) / len(set_a | set_b), 4)


def _normalize_url(url: str) -> str:
    """Normalise a URL to ``netloc/path`` for loose equality comparisons.

    Args:
        url: Raw URL string.

    Returns:
        ``"host/path"`` with ``www.`` and trailing slash stripped, or an
        empty string if *url* has no host.
    """
    parts = urlsplit(url.strip().lower())
    if not parts.netloc:
        return ""
    netloc = parts.netloc.removeprefix("www.")
    path = parts.path.rstrip("/")
    return f"{netloc}{path}"


def _urls(metadata: PackageMetadata) -> dict[str, str]:
    """Collect all URLs referenced by *metadata*, keyed by normalised form.

    Args:
        metadata: Package metadata to scan.

    Returns:
        A mapping of normalised URL to the original (first-seen) URL string.
    """
    raw_urls = [metadata.home_page, *(url for _, url in metadata.project_urls)]
    result: dict[str, str] = {}
    for url in raw_urls:
        if not url:
            continue
        normalized = _normalize_url(url)
        if normalized:
            result.setdefault(normalized, url)
    return result


def shared_repo_url(a: PackageMetadata, b: PackageMetadata) -> str | None:
    """Find a project/home page URL shared between the two packages.

    Args:
        a: Metadata of the first package.
        b: Metadata of the second package.

    Returns:
        The shared URL as it appears in *a*'s metadata, or ``None``.
    """
    urls_a = _urls(a)
    urls_b = _urls(b)
    common = sorted(urls_a.keys() & urls_b.keys())
    if not common:
        return None
    return urls_a[common[0]]


def metadata_completeness(metadata: PackageMetadata) -> float:
    """Fraction of expected metadata fields that are populated.

    Args:
        metadata: Package metadata to score.

    Returns:
        A value in ``[0.0, 1.0]``.
    """
    checks = (
        bool(metadata.author_email or metadata.maintainer_email),
        bool(metadata.summary),
        bool(metadata.home_page or metadata.project_urls),
        bool(metadata.classifiers or metadata.keywords),
    )
    return round(sum(checks) / len(checks), 4)


def completeness_delta(a: PackageMetadata, b: PackageMetadata) -> float:
    """Difference in metadata completeness between *b* and *a*.

    Args:
        a: Metadata of the candidate package.
        b: Metadata of the target (legitimate) package.

    Returns:
        ``metadata_completeness(b) - metadata_completeness(a)``, positive
        when the candidate's metadata is sparser than the target's.
    """
    return round(metadata_completeness(b) - metadata_completeness(a), 4)


def domain_age_days(info: DomainInfo, reference_at: datetime) -> int | None:
    """Age of a domain's registration relative to *reference_at*.

    Args:
        info: RDAP domain info.
        reference_at: Point in time to measure against (typically the
            candidate package's first release date).

    Returns:
        Number of days between registration and *reference_at* (negative if
        the domain was registered after *reference_at*), or ``None`` if the
        registration date is unknown.
    """
    if info.registered_at is None:
        return None
    return (reference_at - info.registered_at).days


def confidence_boost(
    *,
    description_similarity: float | None,
    classifier_overlap: float | None,
    shared_repo_url: str | None,
    completeness_delta: float | None,
    author_domain_age_days: int | None,
) -> float:
    """Combine metadata/domain signals into an additive confidence boost.

    Args:
        description_similarity: See :func:`description_similarity`.
        classifier_overlap: See :func:`keyword_classifier_overlap`.
        shared_repo_url: See :func:`shared_repo_url`.
        completeness_delta: See :func:`completeness_delta`.
        author_domain_age_days: See :func:`domain_age_days`.

    Returns:
        A value in ``[0.0, 0.35]``.
    """
    boost = 0.0
    if shared_repo_url is not None:
        boost += 0.25
    if author_domain_age_days is not None:
        if author_domain_age_days < 0:
            boost += 0.20
        elif author_domain_age_days < 30:
            boost += 0.15
    if description_similarity is not None:
        if description_similarity > 0.6:
            boost += 0.15
        elif description_similarity > 0.3:
            boost += 0.05
    if classifier_overlap is not None and classifier_overlap > 0.7:
        boost += 0.05
    if completeness_delta is not None and completeness_delta > 0.5:
        boost += 0.05
    return round(min(boost, _MAX_BOOST), 4)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_pypi_metadata.py -v`
Expected: PASS, all tests (7 from Task 4 + 15 new = 22).

Run: `uv run ruff check nidhogg/enrichment/pypi_metadata.py && uv run mypy nidhogg/enrichment/pypi_metadata.py`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/enrichment/pypi_metadata.py tests/test_pypi_metadata.py
git commit -m "feat(enrichment): add pure typosquat metadata signal functions"
```

---

### Task 6: `enrich_typosquat` orchestration

**Files:**
- Modify: `nidhogg/enrichment/pypi_metadata.py`
- Test: `tests/test_pypi_metadata.py`

**Interfaces:**
- Consumes: `TyposquatFinding` (Task 1), `fetch_package_metadata`/`fetch_domain_info` (Task 4), signal functions (Task 5).
- Produces: `enrich_typosquat(finding: TyposquatFinding) -> TyposquatFinding`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_pypi_metadata.py`:

```python
from nidhogg.core.models import TyposquatFinding, TyposquatMethod
from nidhogg.enrichment.pypi_metadata import enrich_typosquat


def _finding(**overrides: object) -> TyposquatFinding:
    defaults: dict[str, object] = {
        "package_name": "requestz",
        "similar_to": "requests",
        "distance": 1,
        "method": TyposquatMethod.LEVENSHTEIN,
        "confidence": 0.6,
    }
    defaults.update(overrides)
    return TyposquatFinding(**defaults)  # type: ignore[arg-type]


def test_enrich_typosquat_sets_adjusted_confidence_from_boost():
    candidate_meta = _meta(
        name="requestz",
        author_email="dev@brand-new-domain.example",
        summary="fast http client for python",
        home_page="https://github.com/x/requestz",
        first_release_at=datetime(2024, 6, 1, tzinfo=UTC),
    )
    target_meta = _meta(
        name="requests",
        summary="fast http client for python",
        home_page="https://github.com/x/requestz",
    )
    domain_info = DomainInfo(registered_at=datetime(2024, 5, 30, tzinfo=UTC))

    def _fake_fetch(name: str) -> PackageMetadata | None:
        return candidate_meta if name == "requestz" else target_meta

    with (
        patch(
            "nidhogg.enrichment.pypi_metadata.fetch_package_metadata",
            side_effect=_fake_fetch,
        ),
        patch(
            "nidhogg.enrichment.pypi_metadata.fetch_domain_info",
            return_value=domain_info,
        ),
    ):
        result = enrich_typosquat(_finding())

    assert result.adjusted_confidence is not None
    assert result.adjusted_confidence > result.confidence
    assert result.shared_repo_url == "https://github.com/x/requestz"
    assert result.description_similarity == 1.0
    assert result.author_domain_age_days == 2


def test_enrich_typosquat_falls_back_when_metadata_missing():
    with patch(
        "nidhogg.enrichment.pypi_metadata.fetch_package_metadata",
        return_value=None,
    ):
        result = enrich_typosquat(_finding())

    assert result.adjusted_confidence == result.confidence
    assert result.shared_repo_url is None
    assert result.description_similarity is None


def test_enrich_typosquat_preserves_lexical_fields():
    with patch(
        "nidhogg.enrichment.pypi_metadata.fetch_package_metadata",
        return_value=None,
    ):
        result = enrich_typosquat(_finding())

    assert result.package_name == "requestz"
    assert result.similar_to == "requests"
    assert result.distance == 1
    assert result.method == TyposquatMethod.LEVENSHTEIN
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_pypi_metadata.py -k enrich_typosquat -v`
Expected: FAIL with `ImportError: cannot import name 'enrich_typosquat'`.

- [ ] **Step 3: Implement**

Add `from dataclasses import dataclass, replace` (replace the existing `from dataclasses import dataclass` import line) and a `TYPE_CHECKING` import block near the top of `nidhogg/enrichment/pypi_metadata.py`:

```python
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from nidhogg.core.models import TyposquatFinding
```

Append at the end of `nidhogg/enrichment/pypi_metadata.py`:

```python
def enrich_typosquat(finding: TyposquatFinding) -> TyposquatFinding:
    """Enrich *finding* with live PyPI/RDAP signals, best-effort.

    Fetches metadata for both the candidate and the target package, and
    RDAP registration data for the candidate's author/maintainer email
    domain. Any failure leaves the corresponding field(s) at ``None`` and
    ``adjusted_confidence`` equal to the base ``confidence``.

    Args:
        finding: A finding produced by ``check_typosquatting`` with
            ``confidence`` already set.

    Returns:
        A copy of *finding* with the metadata fields and
        ``adjusted_confidence`` populated.
    """
    candidate_meta = fetch_package_metadata(finding.package_name)
    target_meta = fetch_package_metadata(finding.similar_to)

    if candidate_meta is None or target_meta is None:
        return replace(finding, adjusted_confidence=finding.confidence)

    desc_sim = description_similarity(candidate_meta, target_meta)
    overlap = keyword_classifier_overlap(candidate_meta, target_meta)
    repo = shared_repo_url(candidate_meta, target_meta)
    delta = completeness_delta(candidate_meta, target_meta)

    domain = extract_email_domain(candidate_meta.author_email) or extract_email_domain(
        candidate_meta.maintainer_email
    )
    age_days: int | None = None
    if domain is not None and candidate_meta.first_release_at is not None:
        domain_info = fetch_domain_info(domain)
        if domain_info is not None:
            age_days = domain_age_days(domain_info, candidate_meta.first_release_at)

    boost = confidence_boost(
        description_similarity=desc_sim,
        classifier_overlap=overlap,
        shared_repo_url=repo,
        completeness_delta=delta,
        author_domain_age_days=age_days,
    )

    return replace(
        finding,
        adjusted_confidence=round(min(finding.confidence + boost, 0.99), 4),
        description_similarity=desc_sim,
        classifier_overlap=overlap,
        shared_repo_url=repo,
        completeness_delta=delta,
        author_domain_age_days=age_days,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_pypi_metadata.py -v`
Expected: PASS, all tests (22 from Task 5 + 3 new = 25).

Run: `uv run ruff check nidhogg/enrichment/pypi_metadata.py && uv run mypy nidhogg/enrichment/pypi_metadata.py`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/enrichment/pypi_metadata.py tests/test_pypi_metadata.py
git commit -m "feat(enrichment): add enrich_typosquat orchestration"
```

---

### Task 7: CLI integration — `--no-typosquat-intel`

**Files:**
- Modify: `nidhogg/cli.py`
- Test: `tests/test_cli.py` (new file)

**Interfaces:**
- Consumes: `enrich_typosquat` (Task 6).
- Produces: `_analyse_one(..., typosquat_intel: bool = True)`; new CLI flag `--no-typosquat-intel` (`args.typosquat_intel`, default `True`).

- [ ] **Step 1: Write the failing test**

Create `tests/test_cli.py`:

```python
"""Tests for cli.py's typosquat-intel wiring."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from nidhogg.cli import _analyse_one, _build_parser
from nidhogg.core.models import TyposquatFinding, TyposquatMethod


def test_build_parser_typosquat_intel_defaults_true():
    parser = _build_parser()
    args = parser.parse_args(["some/path"])
    assert args.typosquat_intel is True


def test_build_parser_no_typosquat_intel_sets_false():
    parser = _build_parser()
    args = parser.parse_args(["some/path", "--no-typosquat-intel"])
    assert args.typosquat_intel is False


def test_analyse_one_enriches_when_typosquat_found(tmp_path: Path):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    finding = TyposquatFinding(
        package_name="requestz",
        similar_to="requests",
        distance=1,
        method=TyposquatMethod.LEVENSHTEIN,
        confidence=0.6,
    )
    enriched = TyposquatFinding(
        package_name="requestz",
        similar_to="requests",
        distance=1,
        method=TyposquatMethod.LEVENSHTEIN,
        confidence=0.6,
        adjusted_confidence=0.8,
    )
    with (
        patch("nidhogg.analysis.typosquat.check_typosquatting", return_value=finding),
        patch(
            "nidhogg.enrichment.pypi_metadata.enrich_typosquat",
            return_value=enriched,
        ) as mock_enrich,
    ):
        result = _analyse_one(pkg_dir, package_name="requestz")

    assert result is not None
    analysis, _verdict = result
    mock_enrich.assert_called_once_with(finding)
    assert analysis.typosquat is not None
    assert analysis.typosquat.adjusted_confidence == 0.8


def test_analyse_one_skips_enrichment_when_flag_disabled(tmp_path: Path):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    finding = TyposquatFinding(
        package_name="requestz",
        similar_to="requests",
        distance=1,
        method=TyposquatMethod.LEVENSHTEIN,
        confidence=0.6,
    )
    with (
        patch("nidhogg.analysis.typosquat.check_typosquatting", return_value=finding),
        patch(
            "nidhogg.enrichment.pypi_metadata.enrich_typosquat"
        ) as mock_enrich,
    ):
        result = _analyse_one(
            pkg_dir, package_name="requestz", typosquat_intel=False
        )

    assert result is not None
    mock_enrich.assert_not_called()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py -v`
Expected: FAIL — `test_build_parser_typosquat_intel_defaults_true` fails with `AttributeError: 'Namespace' object has no attribute 'typosquat_intel'`; the `_analyse_one` tests fail with `TypeError: _analyse_one() got an unexpected keyword argument 'typosquat_intel'`.

- [ ] **Step 3: Implement**

In `nidhogg/cli.py`, add the new argument in `_build_parser` (after the `--update-top-packages` block, before `return parser`):

```python
    parser.add_argument(
        "--no-typosquat-intel",
        action="store_false",
        dest="typosquat_intel",
        help=(
            "Skip live PyPI/RDAP metadata enrichment for typosquat findings "
            "(enabled by default; requires network access when a match is found)."
        ),
    )
    return parser
```

Update `_analyse_one`'s signature and body:

```python
def _analyse_one(
    package_path: Path,
    *,
    benign_domains_path: Path | None = None,
    check_ssl: bool = False,
    package_name: str | None = None,
    typosquat_intel: bool = True,
) -> tuple[PackageAnalysis, Verdict] | None:
    """Run the analysis pipeline for a single package directory.

    Args:
        package_path: Directory of the package to analyse.
        benign_domains_path: Optional path to a custom benign domain list.
        check_ssl: When ``True``, query TLS certificates for each HTTPS domain
            and raise confidence for Let's Encrypt issuers.
        package_name: When provided, run the typosquatting check with this name.
        typosquat_intel: When ``True`` (default) and a typosquat match is
            found, enrich it with live PyPI/RDAP metadata signals.

    Returns:
        A ``(PackageAnalysis, Verdict)`` tuple, or ``None`` on read error.
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

    if package_name is not None:
        from nidhogg.analysis.typosquat import check_typosquatting  # noqa: PLC0415

        analysis.typosquat = check_typosquatting(package_name)
        if analysis.typosquat is not None and typosquat_intel:
            from nidhogg.enrichment.pypi_metadata import enrich_typosquat  # noqa: PLC0415

            analysis.typosquat = enrich_typosquat(analysis.typosquat)

    verdict = classify(analysis)

    return analysis, verdict
```

Update `_run_analyze` to accept and forward `typosquat_intel`:

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

    if output is not None:
        write_results(analysis, output)
    elif as_json:
        print(json.dumps(build_document(analysis), indent=2))  # noqa: T201
    else:
        use_color = sys.stdout.isatty()
        print(format_results(analysis, color=use_color))  # noqa: T201

    return 0 if verdict is Verdict.CLEAN else 1
```

Update `_run_batch` similarly — add `typosquat_intel: bool = True` to its signature and docstring, and pass it through to `_analyse_one`:

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
) -> int:
```

(Add the matching `typosquat_intel` line to the docstring's Args section, and add `typosquat_intel=typosquat_intel,` to the `_analyse_one(...)` call inside its loop.)

Finally, update `main()` to read and forward the new flag:

```python
def main() -> None:
    """Entry point for the ``nidhogg`` CLI."""
    parser = _build_parser()
    args = parser.parse_args()
    package_path: Path = args.package_path
    output: Path | None = args.output
    as_json: bool = args.json
    verbose: bool = args.verbose
    benign_domains: Path | None = args.benign_domains
    check_ssl: bool = args.check_ssl
    batch: bool = args.batch
    update_top: bool = args.update_top_packages
    typosquat_intel: bool = args.typosquat_intel

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
            )
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli.py -v`
Expected: PASS, all 4 tests.

Run: `uv run pytest tests/ -v`
Expected: full suite PASS (nothing else references `_analyse_one`/`_run_batch`/`_run_analyze` positionally in a way the new keyword-only param would break).

Run: `uv run ruff check nidhogg/cli.py && uv run mypy nidhogg/cli.py`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/cli.py tests/test_cli.py
git commit -m "feat(cli): add --no-typosquat-intel flag and wire enrich_typosquat"
```

---

### Task 8: Scoring — metadata corroboration bonus

**Files:**
- Modify: `nidhogg/data/scoring.toml:56-67`
- Modify: `nidhogg/scoring.py`
- Test: `tests/test_scoring.py`

**Interfaces:**
- Consumes: `TyposquatFinding.adjusted_confidence`/`.confidence` (Task 1).
- Produces: `ComboBonus.typosquat_metadata_weight: float`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_scoring.py`:

```python
from nidhogg.scoring import load_scoring_config


def test_score_typosquat_metadata_boost_aplica_bonus_extra() -> None:
    typosquat = TyposquatFinding(
        package_name="requestz",
        similar_to="requests",
        distance=1,
        method=TyposquatMethod.LEVENSHTEIN,
        confidence=0.6,
        adjusted_confidence=0.85,
    )
    pkg = _pkg(typosquat=typosquat)
    cfg = load_scoring_config()
    expected = cfg.score.combo_bonuses.typosquat_close + (
        0.85 - 0.6
    ) * cfg.score.combo_bonuses.typosquat_metadata_weight
    assert compute_score(pkg) == pytest.approx(expected)


def test_score_typosquat_sin_enriquecer_no_aplica_bonus_extra() -> None:
    typosquat = TyposquatFinding(
        package_name="requestz",
        similar_to="requests",
        distance=1,
        method=TyposquatMethod.LEVENSHTEIN,
        confidence=0.6,
    )
    pkg = _pkg(typosquat=typosquat)
    cfg = load_scoring_config()
    assert compute_score(pkg) == pytest.approx(cfg.score.combo_bonuses.typosquat_close)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_scoring.py -k typosquat_metadata_boost -v`
Expected: FAIL with `AttributeError: 'ComboBonus' object has no attribute 'typosquat_metadata_weight'`.

- [ ] **Step 3: Implement**

In `nidhogg/data/scoring.toml`, add a line under `[score.combo_bonuses]` (after `typosquat_far`):

```toml
# Bonus when PyPI/RDAP metadata corroborates the typosquat match, scaled by
# how much adjusted_confidence exceeds the base lexical confidence.
typosquat_metadata_weight = 1.0
```

In `nidhogg/scoring.py`, add the field to `ComboBonus` (after `typosquat_far: float`):

```python
@dataclass(frozen=True)
class ComboBonus:
    """Bonus scores applied when multiple risk signals combine."""

    high_severity_url: float
    dynamic_execution: float
    typosquat_close: float
    typosquat_far: float
    typosquat_metadata_weight: float
    domain_floor: float
```

Update `_parse_config`'s `ComboBonus(...)` construction:

```python
            combo_bonuses=ComboBonus(
                high_severity_url=float(cb["high_severity_url"]),
                dynamic_execution=float(cb["dynamic_execution"]),
                typosquat_close=float(cb["typosquat_close"]),
                typosquat_far=float(cb["typosquat_far"]),
                typosquat_metadata_weight=float(cb["typosquat_metadata_weight"]),
                domain_floor=float(cb["domain_floor"]),
            ),
```

Update `compute_score`'s typosquat block:

```python
    # Typosquatting proximity.
    if analysis.typosquat is not None:
        if analysis.typosquat.distance <= 1:
            bonus += sc.combo_bonuses.typosquat_close
        else:
            bonus += sc.combo_bonuses.typosquat_far
        if analysis.typosquat.adjusted_confidence is not None:
            extra = (
                analysis.typosquat.adjusted_confidence - analysis.typosquat.confidence
            )
            bonus += extra * sc.combo_bonuses.typosquat_metadata_weight
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_scoring.py -v`
Expected: PASS, all tests including the 2 new ones. The pre-existing `test_score_typosquat_cercano_aplica_bonus` and `test_score_capeado_en_0_99` still pass unchanged (`adjusted_confidence` defaults to `None`, so `extra` is never added there).

Run: `uv run pytest tests/ -v`
Expected: full suite PASS.

Run: `uv run ruff check nidhogg/scoring.py nidhogg/data/scoring.toml && uv run mypy nidhogg/scoring.py`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/data/scoring.toml nidhogg/scoring.py tests/test_scoring.py
git commit -m "feat(scoring): add typosquat metadata corroboration bonus"
```

---

## Final Verification

- [ ] Run the complete suite once more: `uv run pytest tests/ -v`
- [ ] Run `uv run ruff check .` and `uv run ruff format --check .`
- [ ] Run `uv run mypy nidhogg/`
- [ ] Manually smoke-test: `uv run nidhogg <any extracted package dir>` still runs end-to-end (typosquat check with no network mocked will attempt real PyPI/RDAP calls only if a lexical match is found — expected to no-op gracefully offline).
