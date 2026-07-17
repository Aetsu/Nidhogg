# Nidhogg URL-Focus Simplification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Strip Nidhogg down to a single concern — finding URLs in Python packages and classifying each package as `malicious` / `not_malicious` — by removing the behavioral-pattern (layer 3) and typosquatting subsystems, and simplifying the scoring/classifier/output/CLI code that referenced them.

**Architecture:** The pipeline becomes `walker → [layer1_regex, layer2_ast] → aggregator → enrichment(ssl_cert) → classifier → output`. `fetching/` (fetch/monitor subcommands) and `output/history.py` are untouched. Everything else is either deleted outright (layer 3, typosquat) or trimmed to drop the fields/branches those subsystems fed.

**Tech Stack:** Python 3.14, uv, pytest, loguru, ruff, mypy (see `CLAUDE.md`).

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-14-url-focus-simplification-design.md` — every task below implements one section of it.
- Verdict becomes binary: `Verdict.MALICIOUS` / `Verdict.NOT_MALICIOUS` (was `MALICIOUS`/`SUSPICIOUS`/`CLEAN`).
- Risk display becomes binary: `"malicious"` / `"clean"` (was `"high"`/`"medium"`/`"low"`/`"clean"`).
- Decision made during planning (not explicit in the spec, but a direct consequence of it): `fetch`/`monitor`'s `--no-check-urls`/`--no-check-typosquat`/`--no-typosquat-intel` flags, and the `package_name`/`_infer_package_name` plumbing that only existed to feed the typosquat check, are removed entirely — once typosquat is gone, skipping URL analysis would leave nothing to check.
- Every module you touch already follows: Google-style docstrings, strict type hints, no dict-based data models (dataclasses only), no obvious comments. Match this style in new/changed code.
- Run `uv run pytest <file>` (not the full suite) after each task's changes, and the full suite only in the final task — the full suite is slow because of fixture-heavy tests.
- Commit after every task (see each task's last step). Use `git rm` for deletions so the removal is staged correctly.

---

### Task 1: Simplify core data models

**Files:**
- Modify: `nidhogg/core/models.py`
- Modify: `tests/test_models.py`

**Interfaces:**
- Produces: `PackageAnalysis(name: str, path: Path, findings: list[UrlFinding] = [], uses_dynamic_execution: bool = False, score: float = 0.0)` — no more `pattern_findings`/`typosquat` fields. `AnalysisLayer`, `DetectionMethod`, `DomainThreatCategory`, `UrlFinding` unchanged. `PatternCategory`, `PatternFinding`, `TyposquatMethod`, `TyposquatFinding` no longer exist.

- [ ] **Step 1: Replace `nidhogg/core/models.py`**

```python
"""Shared data models for the Nidhogg analysis pipeline."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


class AnalysisLayer(enum.Enum):
    """The pipeline layer that produced a finding."""

    REGEX = "regex"
    AST = "ast"


class DetectionMethod(enum.Enum):
    """The technique used to detect a URL within a layer."""

    LITERAL = "literal"
    CONCAT = "concat"
    BASE64 = "base64"
    FSTRING = "fstring"
    SCOPE_TRACKING = "scope_tracking"
    IP = "ip"


class DomainThreatCategory(enum.Enum):
    """Threat category assigned to a URL's host by the domain classifier."""

    SHORTENER = "shortener"
    TUNNELING = "tunneling"
    EXFILTRATION = "exfiltration"
    IP_RECON = "ip_recon"
    MALWARE_HOSTING = "malware_hosting"
    SUSPICIOUS_TLD = "suspicious_tld"
    RAW_IP = "raw_ip"


@dataclass
class UrlFinding:
    """A single URL candidate found during package analysis.

    Attributes:
        value: The extracted URL string.
        filepath: Path to the source file where the URL was found.
        lineno: Line number in the source file (1-indexed).
        layer: Which analysis layer produced this finding.
        method: Which detection technique resolved the URL.
        confidence: Detection confidence in the range [0.0, 1.0].
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
    confidence: float
    cert_issuer: str | None = None
    domain_threat: DomainThreatCategory | None = None


@dataclass
class PackageAnalysis:
    """Aggregated results of analysing a single package directory.

    Attributes:
        name: Package name (derived from the directory name).
        path: Absolute path to the package directory.
        findings: All URL findings collected across every source file.
        uses_dynamic_execution: True when at least one file contained
            ``eval`` or ``exec`` calls that could not be statically resolved.
        score: Global risk score in the range [0.0, 0.99], computed by
            ``compute_score()`` and stored by ``classify()``.  Defaults to
            ``0.0`` until the classifier runs.
    """

    name: str
    path: Path
    findings: list[UrlFinding] = field(default_factory=list)
    uses_dynamic_execution: bool = False
    score: float = 0.0
```

- [ ] **Step 2: Replace `tests/test_models.py`**

```python
"""Tests for core data models and exceptions."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from nidhogg.core.exceptions import NidhoggError, PackageReadError, ParseError
from nidhogg.core.models import (
    AnalysisLayer,
    DetectionMethod,
    PackageAnalysis,
    UrlFinding,
)

# ---------------------------------------------------------------------------
# AnalysisLayer
# ---------------------------------------------------------------------------


def test_analysis_layer_values():
    assert AnalysisLayer.REGEX.value == "regex"
    assert AnalysisLayer.AST.value == "ast"


def test_analysis_layer_members():
    assert set(AnalysisLayer) == {AnalysisLayer.REGEX, AnalysisLayer.AST}


# ---------------------------------------------------------------------------
# DetectionMethod
# ---------------------------------------------------------------------------


def test_detection_method_values():
    assert DetectionMethod.LITERAL.value == "literal"
    assert DetectionMethod.CONCAT.value == "concat"
    assert DetectionMethod.BASE64.value == "base64"
    assert DetectionMethod.FSTRING.value == "fstring"
    assert DetectionMethod.SCOPE_TRACKING.value == "scope_tracking"


def test_detection_method_members():
    expected = {
        DetectionMethod.LITERAL,
        DetectionMethod.CONCAT,
        DetectionMethod.BASE64,
        DetectionMethod.FSTRING,
        DetectionMethod.SCOPE_TRACKING,
        DetectionMethod.IP,
    }
    assert set(DetectionMethod) == expected


# ---------------------------------------------------------------------------
# UrlFinding construction
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_finding(tmp_path: Path) -> UrlFinding:
    return UrlFinding(
        value="https://evil.example.com/payload",
        filepath=tmp_path / "setup.py",
        lineno=42,
        layer=AnalysisLayer.REGEX,
        method=DetectionMethod.LITERAL,
        confidence=0.9,
    )


def test_url_finding_construction(sample_finding: UrlFinding):
    assert sample_finding.value == "https://evil.example.com/payload"
    assert sample_finding.lineno == 42
    assert sample_finding.layer is AnalysisLayer.REGEX
    assert sample_finding.method is DetectionMethod.LITERAL
    assert sample_finding.confidence == 0.9


def test_url_finding_serialization(sample_finding: UrlFinding, tmp_path: Path):
    d = dataclasses.asdict(sample_finding)
    assert d["value"] == "https://evil.example.com/payload"
    assert d["lineno"] == 42
    assert d["layer"] is AnalysisLayer.REGEX
    assert d["method"] is DetectionMethod.LITERAL
    assert d["confidence"] == 0.9
    assert d["filepath"] == tmp_path / "setup.py"


# ---------------------------------------------------------------------------
# PackageAnalysis construction
# ---------------------------------------------------------------------------


def test_package_analysis_defaults(tmp_path: Path):
    analysis = PackageAnalysis(name="mypkg", path=tmp_path)
    assert analysis.name == "mypkg"
    assert analysis.path == tmp_path
    assert analysis.findings == []
    assert analysis.uses_dynamic_execution is False


def test_package_analysis_with_findings(tmp_path: Path, sample_finding: UrlFinding):
    analysis = PackageAnalysis(
        name="mypkg",
        path=tmp_path,
        findings=[sample_finding],
        uses_dynamic_execution=True,
    )
    assert len(analysis.findings) == 1
    assert analysis.uses_dynamic_execution is True


def test_package_analysis_findings_not_shared(tmp_path: Path):
    """Default mutable list must not be shared between instances."""
    a = PackageAnalysis(name="a", path=tmp_path)
    b = PackageAnalysis(name="b", path=tmp_path)
    a.findings.append(
        UrlFinding(
            value="https://x.com",
            filepath=tmp_path / "x.py",
            lineno=1,
            layer=AnalysisLayer.AST,
            method=DetectionMethod.CONCAT,
            confidence=0.5,
        )
    )
    assert b.findings == []


def test_package_analysis_serialization(tmp_path: Path, sample_finding: UrlFinding):
    analysis = PackageAnalysis(name="mypkg", path=tmp_path, findings=[sample_finding])
    d = dataclasses.asdict(analysis)
    assert d["name"] == "mypkg"
    assert d["uses_dynamic_execution"] is False
    assert len(d["findings"]) == 1
    assert d["findings"][0]["value"] == "https://evil.example.com/payload"


# ---------------------------------------------------------------------------
# Exceptions hierarchy
# ---------------------------------------------------------------------------


def test_package_read_error_is_nidhogg_error():
    assert issubclass(PackageReadError, NidhoggError)


def test_parse_error_is_nidhogg_error():
    assert issubclass(ParseError, NidhoggError)


def test_nidhogg_error_is_exception():
    assert issubclass(NidhoggError, Exception)


def test_exceptions_can_be_raised_and_caught():
    with pytest.raises(NidhoggError):
        raise PackageReadError("cannot read /tmp/pkg")

    with pytest.raises(NidhoggError):
        raise ParseError("syntax error in setup.py")
```

- [ ] **Step 3: Run the tests**

Run: `uv run pytest tests/test_models.py -v`
Expected: All tests PASS (no more typosquat-related tests).

- [ ] **Step 4: Commit**

```bash
git add nidhogg/core/models.py tests/test_models.py
git commit -m "$(cat <<'EOF'
refactor(models)!: drop PatternFinding/TyposquatFinding from data model

Nidhogg is narrowing to URL detection only. PackageAnalysis no longer
carries pattern_findings or typosquat fields.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Simplify the scoring engine

**Files:**
- Modify: `nidhogg/scoring.py`
- Modify: `nidhogg/data/scoring.toml`
- Modify: `tests/test_scoring.py`

**Interfaces:**
- Consumes: `PackageAnalysis` from Task 1 (`findings`, `uses_dynamic_execution`, no `pattern_findings`/`typosquat`).
- Produces: `ScoringConfig(thresholds: Thresholds, domain_boosts: DomainBoosts, ssl: SslConfig, score: ScoreWeights)`, `Thresholds(malicious_url: float, high_display: float, medium_display: float)`, `DomainBoosts(high: float, normal: float, confidence_cap: float)`, `SslConfig(confidence_bump: float)`, `ScoreWeights(domain_floor: float)`, `load_scoring_config(path: Path | None = None) -> ScoringConfig`, `compute_score(analysis: PackageAnalysis) -> float`. These are consumed unchanged by `aggregator.py` and `enrichment/ssl_cert.py` (both already only use `domain_boosts`/`ssl.confidence_bump`, untouched by this task) and by `classifier.py`/`output/writer.py` (updated in Tasks 3 and 7).

- [ ] **Step 1: Replace `nidhogg/data/scoring.toml`**

```toml
# Scoring weights and thresholds for Nidhogg.
# Edit this file to tune sensitivity without touching Python code.

[thresholds]
# Minimum confidence for a URL finding to classify the package as MALICIOUS.
malicious_url = 0.85
# Confidence threshold for "high risk" display in terminal output.
high_display = 0.85
# Confidence threshold for "medium risk" display in terminal output.
medium_display = 0.7

[domain_boosts]
# Confidence boost for EXFILTRATION / MALWARE_HOSTING domain threat categories.
high = 0.2
# Confidence boost for all other domain threat categories.
normal = 0.1
# Maximum confidence value (cap applied after every boost).
confidence_cap = 0.99

[ssl]
# Confidence bump applied when a domain's TLS certificate is issued by Let's Encrypt.
confidence_bump = 0.05

[score]
# Minimum score floor when an EXFILTRATION/MALWARE_HOSTING domain is present.
# Kept above thresholds.malicious_url so the numeric score always agrees with
# the MALICIOUS verdict this case forces.
domain_floor = 0.9
```

- [ ] **Step 2: Replace `nidhogg/scoring.py`**

```python
"""Scoring configuration: weights and thresholds loaded from scoring.toml."""

from __future__ import annotations

import functools
import tomllib
from dataclasses import dataclass
from importlib.resources import files
from typing import TYPE_CHECKING, Any

from nidhogg.core.models import DomainThreatCategory

if TYPE_CHECKING:
    from pathlib import Path

    from nidhogg.core.models import PackageAnalysis


@dataclass(frozen=True)
class Thresholds:
    """Confidence thresholds for classification decisions and display."""

    malicious_url: float
    high_display: float
    medium_display: float


@dataclass(frozen=True)
class DomainBoosts:
    """Confidence boosts applied when a domain threat category is detected."""

    high: float
    normal: float
    confidence_cap: float


@dataclass(frozen=True)
class SslConfig:
    """SSL certificate enrichment parameters."""

    confidence_bump: float


@dataclass(frozen=True)
class ScoreWeights:
    """Weights for the global package score computation."""

    domain_floor: float


@dataclass(frozen=True)
class ScoringConfig:
    """Complete scoring configuration loaded from scoring.toml."""

    thresholds: Thresholds
    domain_boosts: DomainBoosts
    ssl: SslConfig
    score: ScoreWeights


def _parse_config(data: dict[str, Any]) -> ScoringConfig:
    """Build a :class:`ScoringConfig` from a raw TOML dict.

    Args:
        data: Parsed TOML document as a plain dict.

    Returns:
        Fully populated :class:`ScoringConfig` instance.
    """
    t: dict[str, Any] = data["thresholds"]
    db: dict[str, Any] = data["domain_boosts"]
    s: dict[str, Any] = data["ssl"]
    sc: dict[str, Any] = data["score"]

    return ScoringConfig(
        thresholds=Thresholds(
            malicious_url=float(t["malicious_url"]),
            high_display=float(t["high_display"]),
            medium_display=float(t["medium_display"]),
        ),
        domain_boosts=DomainBoosts(
            high=float(db["high"]),
            normal=float(db["normal"]),
            confidence_cap=float(db["confidence_cap"]),
        ),
        ssl=SslConfig(confidence_bump=float(s["confidence_bump"])),
        score=ScoreWeights(domain_floor=float(sc["domain_floor"])),
    )


_MALICIOUS_DOMAIN_THREATS = frozenset(
    [DomainThreatCategory.EXFILTRATION, DomainThreatCategory.MALWARE_HOSTING]
)


@functools.cache
def load_scoring_config(path: Path | None = None) -> ScoringConfig:
    """Load and return the scoring configuration, caching the result.

    On the first call the TOML file is parsed; subsequent calls with the same
    *path* return the cached instance without re-reading the file.

    Args:
        path: Path to a custom ``scoring.toml``.  When ``None``, the file
            bundled with the package (``nidhogg/data/scoring.toml``) is used.

    Returns:
        A fully populated :class:`ScoringConfig`.
    """
    if path is None:
        raw: bytes = (
            files("nidhogg").joinpath("data").joinpath("scoring.toml").read_bytes()
        )
        data = tomllib.loads(raw.decode())
    else:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    return _parse_config(data)


def compute_score(analysis: PackageAnalysis) -> float:
    """Compute a global risk score for *analysis* in the range ``[0.0, 0.99]``.

    The score is the confidence of the strongest URL finding, raised to at
    least ``thresholds.malicious_url`` when dynamic execution was detected,
    and to at least ``score.domain_floor`` when an EXFILTRATION/MALWARE_HOSTING
    domain is present — matching exactly the conditions that make
    :func:`nidhogg.classifier.classify` return ``MALICIOUS``.

    Args:
        analysis: Completed (aggregated) package analysis.

    Returns:
        A float in ``[0.0, 0.99]``.
    """
    cfg = load_scoring_config()
    score = max((f.confidence for f in analysis.findings), default=0.0)

    if analysis.uses_dynamic_execution:
        score = max(score, cfg.thresholds.malicious_url)

    if any(f.domain_threat in _MALICIOUS_DOMAIN_THREATS for f in analysis.findings):
        score = max(score, cfg.score.domain_floor)

    return min(score, 0.99)
```

- [ ] **Step 3: Replace `tests/test_scoring.py`**

```python
"""Tests for the compute_score() global scoring function."""

from __future__ import annotations

from pathlib import Path

import pytest

from nidhogg.core.models import (
    AnalysisLayer,
    DetectionMethod,
    DomainThreatCategory,
    PackageAnalysis,
    UrlFinding,
)
from nidhogg.scoring import compute_score, load_scoring_config

_FAKE_PATH = Path("/fake/pkg")
_FAKE_FILE = _FAKE_PATH / "evil.py"


def _url_finding(
    confidence: float, domain_threat: DomainThreatCategory | None = None
) -> UrlFinding:
    return UrlFinding(
        value="http://evil.example.com/x",
        filepath=_FAKE_FILE,
        lineno=1,
        layer=AnalysisLayer.REGEX,
        method=DetectionMethod.LITERAL,
        confidence=confidence,
        domain_threat=domain_threat,
    )


def _pkg(**kwargs: object) -> PackageAnalysis:
    defaults: dict[str, object] = {"name": "testpkg", "path": _FAKE_PATH}
    defaults.update(kwargs)
    return PackageAnalysis(**defaults)  # type: ignore[arg-type]


def test_score_sin_findings_es_cero() -> None:
    pkg = _pkg()
    assert compute_score(pkg) == pytest.approx(0.0)


def test_score_es_la_confianza_maxima() -> None:
    pkg = _pkg(findings=[_url_finding(0.6), _url_finding(0.9)])
    assert compute_score(pkg) == pytest.approx(0.9)


def test_score_dynamic_exec_eleva_al_umbral_malicioso() -> None:
    pkg = _pkg(findings=[_url_finding(0.5)], uses_dynamic_execution=True)
    cfg = load_scoring_config()
    assert compute_score(pkg) == pytest.approx(cfg.thresholds.malicious_url)


def test_score_dynamic_exec_no_baja_una_confianza_ya_alta() -> None:
    pkg = _pkg(findings=[_url_finding(0.95)], uses_dynamic_execution=True)
    assert compute_score(pkg) == pytest.approx(0.95)


def test_score_domain_threat_exfiltration_aplica_floor() -> None:
    pkg = _pkg(findings=[_url_finding(0.1, DomainThreatCategory.EXFILTRATION)])
    cfg = load_scoring_config()
    assert compute_score(pkg) == pytest.approx(cfg.score.domain_floor)


def test_score_domain_threat_malware_hosting_aplica_floor() -> None:
    pkg = _pkg(findings=[_url_finding(0.1, DomainThreatCategory.MALWARE_HOSTING)])
    cfg = load_scoring_config()
    assert compute_score(pkg) == pytest.approx(cfg.score.domain_floor)


def test_score_domain_threat_no_malicioso_no_aplica_floor() -> None:
    pkg = _pkg(findings=[_url_finding(0.3, DomainThreatCategory.SHORTENER)])
    assert compute_score(pkg) == pytest.approx(0.3)


def test_score_capeado_en_0_99() -> None:
    pkg = _pkg(findings=[_url_finding(1.0)])
    assert compute_score(pkg) == pytest.approx(0.99)
```

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/test_scoring.py -v`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/scoring.py nidhogg/data/scoring.toml tests/test_scoring.py
git commit -m "$(cat <<'EOF'
refactor(scoring)!: reduce compute_score to max-confidence + two floors

Combo bonuses, count dampening, and verdict-alignment clamps existed to
support the 3-tier verdict and pattern/typosquat signals, both gone now.
The remaining classifier conditions map 1:1 onto the new formula.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Binary classifier verdict

**Files:**
- Modify: `nidhogg/classifier.py`
- Create: `tests/test_classifier.py` (no test file existed for `classifier.py` before this plan — `classify()` was only exercised indirectly through `test_cli.py`/`test_output_writer.py`/`test_integration.py`)

**Interfaces:**
- Consumes: `PackageAnalysis`, `compute_score`, `load_scoring_config` from Tasks 1–2.
- Produces: `Verdict.MALICIOUS` / `Verdict.NOT_MALICIOUS`, `classify(analysis: PackageAnalysis) -> Verdict` (also sets `analysis.score`). Consumed by `cli.py` (Task 8) and `output/writer.py` (Task 7).

- [ ] **Step 1: Write the failing tests in `tests/test_classifier.py`**

```python
"""Tests for classifier.py's binary verdict logic."""

from __future__ import annotations

from pathlib import Path

import pytest

from nidhogg.classifier import Verdict, classify
from nidhogg.core.models import (
    AnalysisLayer,
    DetectionMethod,
    DomainThreatCategory,
    PackageAnalysis,
    UrlFinding,
)

_FAKE_PATH = Path("/fake/pkg")
_FAKE_FILE = _FAKE_PATH / "evil.py"


def _finding(
    confidence: float, domain_threat: DomainThreatCategory | None = None
) -> UrlFinding:
    return UrlFinding(
        value="http://evil.example.com/x",
        filepath=_FAKE_FILE,
        lineno=1,
        layer=AnalysisLayer.REGEX,
        method=DetectionMethod.LITERAL,
        confidence=confidence,
        domain_threat=domain_threat,
    )


def _pkg(**kwargs: object) -> PackageAnalysis:
    defaults: dict[str, object] = {"name": "testpkg", "path": _FAKE_PATH}
    defaults.update(kwargs)
    return PackageAnalysis(**defaults)  # type: ignore[arg-type]


def test_classify_no_findings_no_dynamic_is_not_malicious():
    pkg = _pkg()
    assert classify(pkg) is Verdict.NOT_MALICIOUS


def test_classify_low_confidence_finding_is_not_malicious():
    pkg = _pkg(findings=[_finding(0.5)])
    assert classify(pkg) is Verdict.NOT_MALICIOUS


def test_classify_high_confidence_finding_is_malicious():
    pkg = _pkg(findings=[_finding(0.9)])
    assert classify(pkg) is Verdict.MALICIOUS


def test_classify_confidence_at_threshold_is_malicious():
    pkg = _pkg(findings=[_finding(0.85)])
    assert classify(pkg) is Verdict.MALICIOUS


def test_classify_dynamic_execution_alone_is_malicious():
    pkg = _pkg(uses_dynamic_execution=True)
    assert classify(pkg) is Verdict.MALICIOUS


def test_classify_dynamic_execution_with_low_confidence_finding_is_malicious():
    pkg = _pkg(findings=[_finding(0.1)], uses_dynamic_execution=True)
    assert classify(pkg) is Verdict.MALICIOUS


def test_classify_exfiltration_domain_threat_is_malicious_even_at_low_confidence():
    pkg = _pkg(findings=[_finding(0.1, DomainThreatCategory.EXFILTRATION)])
    assert classify(pkg) is Verdict.MALICIOUS


def test_classify_malware_hosting_domain_threat_is_malicious():
    pkg = _pkg(findings=[_finding(0.1, DomainThreatCategory.MALWARE_HOSTING)])
    assert classify(pkg) is Verdict.MALICIOUS


def test_classify_shortener_domain_threat_alone_is_not_malicious():
    pkg = _pkg(findings=[_finding(0.3, DomainThreatCategory.SHORTENER)])
    assert classify(pkg) is Verdict.NOT_MALICIOUS


def test_classify_sets_score_on_analysis():
    pkg = _pkg(findings=[_finding(0.9)])
    classify(pkg)
    assert pkg.score == pytest.approx(0.9)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_classifier.py -v`
Expected: FAIL — `ImportError` or `AttributeError` on `Verdict.NOT_MALICIOUS` (current enum only has `MALICIOUS`/`SUSPICIOUS`/`CLEAN`).

- [ ] **Step 3: Replace `nidhogg/classifier.py`**

```python
"""Classifier: assign a verdict to a completed package analysis."""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

from nidhogg.core.models import DomainThreatCategory
from nidhogg.scoring import compute_score, load_scoring_config

if TYPE_CHECKING:
    from nidhogg.core.models import PackageAnalysis


class Verdict(enum.Enum):
    """Final risk verdict for a package."""

    MALICIOUS = "malicious"
    NOT_MALICIOUS = "not_malicious"


# Domain threat categories that trigger MALICIOUS regardless of confidence.
_MALICIOUS_DOMAIN_THREATS = frozenset(
    [DomainThreatCategory.EXFILTRATION, DomainThreatCategory.MALWARE_HOSTING]
)


def classify(analysis: PackageAnalysis) -> Verdict:
    """Determine the overall risk verdict for an analysed package.

    Rules (evaluated in order):

    1. No URL findings and no dynamic execution → ``NOT_MALICIOUS``.
    2. Any URL finding with a ``domain_threat`` of ``EXFILTRATION`` or
       ``MALWARE_HOSTING`` → ``MALICIOUS``.
    3. Dynamic execution (``eval``/``exec``) detected → ``MALICIOUS``.
    4. Any URL finding with confidence ≥ ``thresholds.malicious_url`` →
       ``MALICIOUS``.
    5. Otherwise → ``NOT_MALICIOUS``.

    Args:
        analysis: Completed (and aggregated) package analysis.

    Returns:
        A :class:`Verdict` reflecting the package's risk level.
    """
    cfg = load_scoring_config()

    if not analysis.findings and not analysis.uses_dynamic_execution:
        verdict = Verdict.NOT_MALICIOUS
    elif any(f.domain_threat in _MALICIOUS_DOMAIN_THREATS for f in analysis.findings):
        verdict = Verdict.MALICIOUS
    elif analysis.uses_dynamic_execution:
        verdict = Verdict.MALICIOUS
    elif any(f.confidence >= cfg.thresholds.malicious_url for f in analysis.findings):
        verdict = Verdict.MALICIOUS
    else:
        verdict = Verdict.NOT_MALICIOUS

    analysis.score = compute_score(analysis)
    return verdict
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_classifier.py -v`
Expected: All 10 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/classifier.py tests/test_classifier.py
git commit -m "$(cat <<'EOF'
feat(classifier)!: binary MALICIOUS/NOT_MALICIOUS verdict

Drops the SUSPICIOUS middle tier along with the pattern/typosquat rules
that fed it. Adds the direct test coverage classify() never had.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Drop layer 3 wiring from the walker

**Files:**
- Modify: `nidhogg/analysis/walker.py`
- Test: `tests/test_walker.py` (unchanged — verified in Step 2 below)

**Interfaces:**
- Consumes: `extract_urls_regex`, `extract_urls_ast` (unchanged, from `layer1_regex.py`/`layer2_ast.py`).
- Produces: `analyze_package(path: Path) -> PackageAnalysis` — same signature, but the returned `PackageAnalysis` no longer has `pattern_findings` (removed in Task 1) and pyproject.toml is no longer inspected.

- [ ] **Step 1: Replace `nidhogg/analysis/walker.py`**

```python
"""Package walker: entry point for per-package analysis."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

from loguru import logger

from nidhogg.analysis.layer1_regex import extract_urls_regex
from nidhogg.analysis.layer2_ast import extract_urls_ast
from nidhogg.core.exceptions import PackageReadError
from nidhogg.core.models import PackageAnalysis

if TYPE_CHECKING:
    from pathlib import Path

    from nidhogg.core.models import UrlFinding


def _collect_py_files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*.py") if "__pycache__" not in p.parts]


def _analyze_file(filepath: Path) -> tuple[list[UrlFinding], bool]:
    """Read *filepath* and run both URL-extraction layers.

    Args:
        filepath: Path to the ``.py`` file to analyse.

    Returns:
        A tuple of ``(url_findings, uses_dynamic_execution)``. Returns
        ``([], False)`` if the file cannot be read.
    """
    try:
        source = filepath.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        logger.warning("Skipping non-UTF-8 file {}", filepath)
        return [], False
    except OSError as exc:
        logger.warning("Skipping unreadable file {}: {}", filepath, exc)
        return [], False

    logger.debug("Analysing {}", filepath)

    with ThreadPoolExecutor(max_workers=2) as executor:
        future1 = executor.submit(extract_urls_regex, source, filepath)
        future2 = executor.submit(extract_urls_ast, source, filepath)
        findings1 = future1.result()
        findings2, uses_dynamic = future2.result()

    return [*findings1, *findings2], uses_dynamic


def analyze_package(path: Path) -> PackageAnalysis:
    """Analyse every Python source file inside a package directory.

    Args:
        path: Absolute path to the already-extracted package directory.

    Returns:
        A :class:`PackageAnalysis` collecting all findings from every
        ``.py`` file discovered under *path*.

    Raises:
        PackageReadError: If *path* does not exist or is not a directory.
    """
    if not path.exists():
        msg = f"Package directory not found: {path}"
        raise PackageReadError(msg)
    if not path.is_dir():
        msg = f"Path is not a directory: {path}"
        raise PackageReadError(msg)

    py_files = _collect_py_files(path)
    logger.info("Found {} Python file(s) in {}", len(py_files), path)

    all_findings: list[UrlFinding] = []
    uses_dynamic_execution = False
    for filepath in py_files:
        file_findings, file_dynamic = _analyze_file(filepath)
        all_findings.extend(file_findings)
        uses_dynamic_execution = uses_dynamic_execution or file_dynamic

    return PackageAnalysis(
        name=path.name,
        path=path,
        findings=all_findings,
        uses_dynamic_execution=uses_dynamic_execution,
    )
```

- [ ] **Step 2: Run the existing walker tests unchanged**

`tests/test_walker.py` only mocks `nidhogg.analysis.walker.extract_urls_regex`/`extract_urls_ast` and never asserts on pattern findings or pyproject hooks, so it needs no edits.

Run: `uv run pytest tests/test_walker.py -v`
Expected: All tests PASS with zero changes to the test file.

- [ ] **Step 3: Commit**

```bash
git add nidhogg/analysis/walker.py
git commit -m "$(cat <<'EOF'
refactor(walker)!: drop layer 3 and pyproject-hook scanning

walker.py now only orchestrates the two URL-extraction layers.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Delete layer 3 (behavioral patterns)

**Files:**
- Delete: `nidhogg/analysis/layer3_patterns.py`
- Delete: `tests/test_layer3_patterns.py`, `tests/test_taint_exec.py`, `tests/test_taint_exfil.py`
- Delete: `tests/fixtures/pkg_patterns/`, `tests/fixtures/pkg_obfuscation/`, `tests/fixtures/pkg_taint_exec/`, `tests/fixtures/pkg_exfil/`

No other module imports `nidhogg.analysis.layer3_patterns` after Task 4 (verified: only `walker.py`, which Task 4 already stopped importing it from, and the test files deleted here).

- [ ] **Step 1: Delete the module, its tests, and its exclusive fixtures**

```bash
git rm nidhogg/analysis/layer3_patterns.py
git rm tests/test_layer3_patterns.py tests/test_taint_exec.py tests/test_taint_exfil.py
git rm -r tests/fixtures/pkg_patterns tests/fixtures/pkg_obfuscation tests/fixtures/pkg_taint_exec tests/fixtures/pkg_exfil
```

- [ ] **Step 2: Verify nothing else references the deleted module**

Run: `grep -rn "layer3_patterns\|PatternCategory\|PatternFinding" nidhogg/ tests/`
Expected: no output (empty).

- [ ] **Step 3: Run the full suite to confirm no collection errors**

Run: `uv run pytest --collect-only -q`
Expected: collection succeeds with no `ModuleNotFoundError`/`ImportError`.

- [ ] **Step 4: Commit**

```bash
git commit -m "$(cat <<'EOF'
refactor!: remove layer 3 behavioral-pattern detection

exec/network/filesystem/credential/persistence/obfuscation/exfiltration
pattern detection and its taint-analysis chains never analyzed URLs —
out of scope for a project centered on URL detection.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Delete the typosquatting subsystem

**Files:**
- Delete: `nidhogg/analysis/typosquat.py`, `nidhogg/enrichment/pypi_metadata.py`, `nidhogg/typosquat_config.py`
- Delete: `nidhogg/data/typosquat.toml`, `nidhogg/data/top_pypi_packages.json`
- Delete: `tests/test_typosquat.py`, `tests/test_typosquat_config.py`, `tests/test_pypi_metadata.py`, `tests/test_top_packages_cache.py`

`cli.py` (Task 8), `output/writer.py` (Task 7), and `tests/test_models.py`/`test_scoring.py`/`test_cli.py`/`test_output_writer.py`/`test_integration.py` (Tasks 1–3, 7–9) already stop referencing `TyposquatFinding`/`TyposquatMethod`/these modules by the time this task runs, but this task's own deletions are independent of task order — run this task any time after Task 1.

- [ ] **Step 1: Delete the modules, their data files, and their tests**

```bash
git rm nidhogg/analysis/typosquat.py nidhogg/enrichment/pypi_metadata.py nidhogg/typosquat_config.py
git rm nidhogg/data/typosquat.toml nidhogg/data/top_pypi_packages.json
git rm tests/test_typosquat.py tests/test_typosquat_config.py tests/test_pypi_metadata.py tests/test_top_packages_cache.py
```

- [ ] **Step 2: Verify nothing else references the deleted modules**

Run: `grep -rn "typosquat\|Typosquat\|pypi_metadata" nidhogg/ tests/ -i`
Expected: no output (empty) — if this task runs before Task 8, `cli.py`/`tests/test_cli.py` will still show matches; re-run this check after Task 8 instead in that case.

- [ ] **Step 3: Commit**

```bash
git commit -m "$(cat <<'EOF'
refactor!: remove typosquatting detection

Package-name similarity and RDAP/PyPI-metadata enrichment compared
package names, not URLs — out of scope for a project centered on URL
detection.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Simplify output/writer.py to binary risk display

**Files:**
- Modify: `nidhogg/output/writer.py`
- Modify: `tests/test_output_writer.py`

**Interfaces:**
- Consumes: `PackageAnalysis` (Task 1), `load_scoring_config` (Task 2), `classify` (Task 3, used only in tests).
- Produces: `_risk_level(analysis) -> "malicious" | "clean"`, `format_results(analysis, *, color=False) -> str`, `build_document(analysis) -> dict`, `format_batch_summary(results, *, color=False) -> str`, `write_results(analysis, destination) -> None` — same public surface as before, minus pattern/typosquat sections, consumed unchanged by `cli.py` (Task 8).

- [ ] **Step 1: Replace `nidhogg/output/writer.py`**

```python
"""Output writer: serialize analysis results to disk as JSON."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from nidhogg.scoring import load_scoring_config

if TYPE_CHECKING:
    from pathlib import Path

    from nidhogg.core.models import PackageAnalysis, UrlFinding

# Risk levels.
_RISK_MALICIOUS = "malicious"
_RISK_CLEAN = "clean"

# ANSI escape codes.
_RST = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"

_RISK_COLORS = {
    _RISK_MALICIOUS: _BOLD + _RED,
    _RISK_CLEAN: _GREEN,
}


def _risk_level(analysis: PackageAnalysis) -> str:
    """Derive a display risk label from the package's score.

    Args:
        analysis: Completed package analysis (score must already be set by classify()).

    Returns:
        ``"malicious"`` when the score meets the malicious threshold, else ``"clean"``.
    """
    if analysis.score >= load_scoring_config().thresholds.malicious_url:
        return _RISK_MALICIOUS
    return _RISK_CLEAN


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
        "confidence": finding.confidence,
        "cert_issuer": finding.cert_issuer,
        "domain_threat": finding.domain_threat.value if finding.domain_threat else None,
    }


def _c(text: str, code: str, *, use_color: bool) -> str:
    """Wrap *text* in an ANSI escape code when *use_color* is True."""
    if not use_color:
        return text
    return code + text + _RST


def _fmt_finding(finding: UrlFinding, pkg_path: Path, *, use_color: bool) -> str:
    """Format a single finding as a terminal line."""
    try:
        rel = str(finding.filepath.relative_to(pkg_path))
    except ValueError:
        rel = str(finding.filepath)
    loc = f"{rel}:{finding.lineno}"
    method = finding.method.value
    conf = finding.confidence
    _thresholds = load_scoring_config().thresholds
    conf_code = (
        _RED
        if conf >= _thresholds.high_display
        else (_YELLOW if conf >= _thresholds.medium_display else _DIM)
    )
    conf_str = _c(f"{conf:.2f}", conf_code, use_color=use_color)
    method_str = _c(method, _DIM, use_color=use_color)
    cert_tag = ""
    if finding.cert_issuer is not None and "Let's Encrypt" in finding.cert_issuer:
        cert_tag = _c(" [LE]", _YELLOW, use_color=use_color)
    threat_tag = ""
    if finding.domain_threat is not None:
        label = finding.domain_threat.value.upper()
        threat_tag = _c(f" [{label}]", _RED, use_color=use_color)
    url_part = f"{finding.value}{cert_tag}{threat_tag}"
    return f"  {loc:<22}  {method_str:<13}  {conf_str}  {url_part}"


def _score_bar(score: float, *, use_color: bool) -> str:
    """Render *score* as a 10-block progress bar followed by the percentage.

    Args:
        score: Value in [0.0, 1.0].
        use_color: Emit ANSI colour codes when ``True``.

    Returns:
        A string like ``"████████░░  82%"``.
    """
    filled = round(score * 10)
    bar = "█" * filled + "░" * (10 - filled)
    pct = f"{score * 100:.0f}%"
    color_code = _RED if score >= 0.85 else (_YELLOW if score >= 0.5 else _DIM)  # noqa: PLR2004
    return _c(bar, color_code, use_color=use_color) + f"  {pct}"


def format_results(analysis: PackageAnalysis, *, color: bool = False) -> str:
    """Format *analysis* as a human-readable terminal string.

    Args:
        analysis: Completed package analysis.
        color: Emit ANSI colour codes when ``True``.

    Returns:
        A multi-line string ready to be printed to stdout.
    """
    risk = _risk_level(analysis)
    dyn_flag = analysis.uses_dynamic_execution
    dyn_yes = _c("yes", _RED, use_color=color)
    dyn_no = _c("no", _DIM, use_color=color)
    dyn_text = dyn_yes if dyn_flag else dyn_no

    lines: list[str] = [
        f"package  {_c(analysis.name, _BOLD, use_color=color)}",
        f"path     {_c(str(analysis.path), _DIM, use_color=color)}",
        "",
        f"risk     {_c(risk.upper(), _RISK_COLORS.get(risk, ''), use_color=color)}",
        f"score    {_score_bar(analysis.score, use_color=color)}",
        f"findings {len(analysis.findings)}",
        f"dynamic  {dyn_text}",
    ]

    if analysis.findings:
        lines.append("")
        lines.append(_c("URLs:", _BOLD, use_color=color))
        lines.extend(
            _fmt_finding(f, analysis.path, use_color=color)
            for f in sorted(analysis.findings, key=lambda f: f.confidence, reverse=True)
        )
    else:
        lines += ["", _c("  no url findings", _GREEN, use_color=color)]

    return "\n".join(lines)


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
            "uses_dynamic_execution": analysis.uses_dynamic_execution,
            "risk_level": _risk_level(analysis),
            "score": analysis.score,
        },
        "findings": [_serialise_finding(f, analysis.path) for f in analysis.findings],
    }


def format_batch_summary(
    results: list[tuple[PackageAnalysis, str]],
    *,
    color: bool = False,
) -> str:
    """Format a human-readable summary of a batch analysis run.

    Args:
        results: List of ``(analysis, risk_level)`` pairs, one per package.
        color: Emit ANSI colour codes when ``True``.

    Returns:
        A multi-line string ready to be printed to stdout.
    """
    score_threshold = 0.50

    total = len(results)
    counts: dict[str, int] = {_RISK_MALICIOUS: 0, _RISK_CLEAN: 0}
    total_url_findings = 0
    dynamic_packages: list[str] = []
    # (name, risk, score) — only packages above the score threshold.
    flagged_packages: list[tuple[str, str, float]] = []

    for analysis, risk in results:
        counts[risk] = counts.get(risk, 0) + 1
        total_url_findings += len(analysis.findings)
        if analysis.uses_dynamic_execution:
            dynamic_packages.append(analysis.name)
        if analysis.score > score_threshold:
            flagged_packages.append((analysis.name, risk, analysis.score))

    separator = _c("─" * 50, _DIM, use_color=color)
    lines: list[str] = [
        "",
        separator,
        _c("BATCH SUMMARY", _BOLD, use_color=color),
        separator,
        f"packages analysed   {total}",
        "",
        "by risk level:",
        f"  {_c('MALICIOUS', _BOLD + _RED, use_color=color)}  {counts[_RISK_MALICIOUS]}",
        f"  {_c('CLEAN    ', _GREEN, use_color=color)}  {counts[_RISK_CLEAN]}",
        "",
        f"url findings        {total_url_findings}",
        f"dynamic execution   {len(dynamic_packages)}",
    ]

    risk_order = {_RISK_MALICIOUS: 0, _RISK_CLEAN: 1}
    if flagged_packages:
        # Group by risk, then sort each group by score descending.
        flagged_packages.sort(key=lambda t: (risk_order.get(t[1], 9), -t[2]))
        lines.append("")
        threshold_pct = int(score_threshold * 100)
        lines.append(
            _c(f"packages with score > {threshold_pct}:", _BOLD, use_color=color)
        )
        current_group = ""
        for name, risk, score in flagged_packages:
            if risk != current_group:
                current_group = risk
                group_label = _c(
                    risk.upper(), _RISK_COLORS.get(risk, ""), use_color=color
                )
                lines.append(f"  {group_label}")
            score_pct = int(score * 100)
            lines.append(f"    {name:<33}  {score_pct:>3}")

    lines.append(separator)
    return "\n".join(lines)


def write_results(analysis: PackageAnalysis, destination: Path) -> None:
    """Write analysis results to *destination* as a JSON file.

    The document contains:

    * **package** — name and path of the analysed package.
    * **summary** — finding count, dynamic-execution flag, and overall risk
      level (``"malicious"`` / ``"clean"``).
    * **findings** — each URL with its file, line, detection layer, method,
      and confidence score.

    Args:
        analysis: Completed package analysis.
        destination: Path where the JSON file will be written.  The parent
            directory must already exist.
    """
    destination.write_text(
        json.dumps(build_document(analysis), indent=2), encoding="utf-8"
    )
```

- [ ] **Step 2: Replace `tests/test_output_writer.py`**

```python
"""Tests for output/writer.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nidhogg.classifier import classify
from nidhogg.core.models import AnalysisLayer, DetectionMethod, PackageAnalysis, UrlFinding
from nidhogg.output.writer import build_document, format_results, write_results


def _pkg(
    tmp_path: Path,
    findings: list[UrlFinding] | None = None,
    uses_dynamic: bool = False,
) -> PackageAnalysis:
    return PackageAnalysis(
        name="testpkg",
        path=tmp_path,
        findings=findings or [],
        uses_dynamic_execution=uses_dynamic,
    )


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


# ---------------------------------------------------------------------------
# File creation
# ---------------------------------------------------------------------------


def test_write_results_creates_file(tmp_path: Path):
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path), out)
    assert out.exists()


def test_write_results_valid_json(tmp_path: Path):
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path), out)
    data = json.loads(out.read_text())
    assert isinstance(data, dict)


# ---------------------------------------------------------------------------
# Package section
# ---------------------------------------------------------------------------


def test_output_contains_package_name(tmp_path: Path):
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path), out)
    data = json.loads(out.read_text())
    assert data["package"]["name"] == "testpkg"


def test_output_contains_package_path(tmp_path: Path):
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path), out)
    data = json.loads(out.read_text())
    assert data["package"]["path"] == str(tmp_path)


# ---------------------------------------------------------------------------
# Summary section
# ---------------------------------------------------------------------------


def test_summary_total_findings_zero(tmp_path: Path):
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path), out)
    data = json.loads(out.read_text())
    assert data["summary"]["total_findings"] == 0


def test_summary_total_findings_count(tmp_path: Path):
    findings = [_finding(tmp_path), _finding(tmp_path, url="https://other.evil.com")]
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path, findings=findings), out)
    data = json.loads(out.read_text())
    assert data["summary"]["total_findings"] == 2


def test_summary_uses_dynamic_execution_false(tmp_path: Path):
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path), out)
    data = json.loads(out.read_text())
    assert data["summary"]["uses_dynamic_execution"] is False


def test_summary_uses_dynamic_execution_true(tmp_path: Path):
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path, uses_dynamic=True), out)
    data = json.loads(out.read_text())
    assert data["summary"]["uses_dynamic_execution"] is True


# ---------------------------------------------------------------------------
# Risk level
# ---------------------------------------------------------------------------


def test_risk_level_clean_when_no_findings(tmp_path: Path):
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path), out)
    data = json.loads(out.read_text())
    assert data["summary"]["risk_level"] == "clean"


def test_risk_level_malicious_when_dynamic_execution(tmp_path: Path):
    out = tmp_path / "results.json"
    analysis = _pkg(
        tmp_path, findings=[_finding(tmp_path, confidence=0.5)], uses_dynamic=True
    )
    classify(analysis)
    write_results(analysis, out)
    data = json.loads(out.read_text())
    assert data["summary"]["risk_level"] == "malicious"


def test_risk_level_malicious_when_high_confidence_finding(tmp_path: Path):
    out = tmp_path / "results.json"
    analysis = _pkg(tmp_path, findings=[_finding(tmp_path, confidence=0.95)])
    classify(analysis)
    write_results(analysis, out)
    data = json.loads(out.read_text())
    assert data["summary"]["risk_level"] == "malicious"


def test_risk_level_clean_when_low_confidence(tmp_path: Path):
    out = tmp_path / "results.json"
    analysis = _pkg(tmp_path, findings=[_finding(tmp_path, confidence=0.3)])
    classify(analysis)
    write_results(analysis, out)
    data = json.loads(out.read_text())
    assert data["summary"]["risk_level"] == "clean"


# ---------------------------------------------------------------------------
# Findings section
# ---------------------------------------------------------------------------


def test_findings_empty_list_when_no_findings(tmp_path: Path):
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path), out)
    data = json.loads(out.read_text())
    assert data["findings"] == []


def test_findings_url_present(tmp_path: Path):
    f = _finding(tmp_path, url="https://c2.evil.example.com/beacon")
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path, findings=[f]), out)
    data = json.loads(out.read_text())
    assert data["findings"][0]["url"] == "https://c2.evil.example.com/beacon"


def test_findings_file_is_relative(tmp_path: Path):
    f = _finding(tmp_path)
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path, findings=[f]), out)
    data = json.loads(out.read_text())
    assert data["findings"][0]["file"] == "module.py"


def test_findings_lineno_present(tmp_path: Path):
    f = _finding(tmp_path, lineno=42)
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path, findings=[f]), out)
    data = json.loads(out.read_text())
    assert data["findings"][0]["line"] == 42


def test_findings_layer_is_string(tmp_path: Path):
    f = _finding(tmp_path, layer=AnalysisLayer.REGEX)
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path, findings=[f]), out)
    data = json.loads(out.read_text())
    assert data["findings"][0]["layer"] == "regex"


def test_findings_method_is_string(tmp_path: Path):
    f = _finding(tmp_path, method=DetectionMethod.BASE64)
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path, findings=[f]), out)
    data = json.loads(out.read_text())
    assert data["findings"][0]["method"] == "base64"


def test_findings_confidence_present(tmp_path: Path):
    f = _finding(tmp_path, confidence=0.75)
    out = tmp_path / "results.json"
    write_results(_pkg(tmp_path, findings=[f]), out)
    data = json.loads(out.read_text())
    assert data["findings"][0]["confidence"] == pytest.approx(0.75)
```

- [ ] **Step 3: Run the tests**

Run: `uv run pytest tests/test_output_writer.py -v`
Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add nidhogg/output/writer.py tests/test_output_writer.py
git commit -m "$(cat <<'EOF'
refactor(output)!: binary malicious/clean risk display

Drops the Patterns:/Typosquat: sections and the 4-tier
high/medium/low/clean risk display in favor of the 2-tier verdict.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Simplify the CLI

**Files:**
- Modify: `nidhogg/cli.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- Consumes: `analyze_package` (Task 4), `aggregate`/`load_benign_domains` (unchanged), `classify`/`Verdict` (Task 3), `build_document`/`format_results`/`format_batch_summary`/`write_results`/`_risk_level` (Task 7), `check_certificates` (unchanged), `fetched_package` (unchanged), `ChangelogClient`/`load_state`/`save_state`/`MonitorState` (unchanged).
- Produces: `_build_parser() -> ArgumentParser`, `_analyse_one(package_path, *, benign_domains_path=None, check_ssl=False) -> tuple[PackageAnalysis, Verdict] | None`, `_run_analyze(...) -> int`, `_run_batch(...) -> int`, `_run_fetch(name, version, output, *, as_json, verbose, keep_download, history_dir) -> int`, `_analyse_new_package(name, *, keep_download) -> tuple[PackageAnalysis, Verdict] | None`, `_run_monitor(*, interval, index_file, concurrency, keep_download, as_json, history_dir, verbose) -> int`, `main() -> None`.

- [ ] **Step 1: Replace `nidhogg/cli.py`**

```python
"""Command-line interface for Nidhogg."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from loguru import logger

from nidhogg.analysis.aggregator import aggregate, load_benign_domains
from nidhogg.analysis.walker import analyze_package
from nidhogg.classifier import Verdict, classify
from nidhogg.core.exceptions import PackageReadError
from nidhogg.core.models import PackageAnalysis
from nidhogg.output.writer import (
    _risk_level,
    build_document,
    format_batch_summary,
    format_results,
    write_results,
)

_EXIT_ERROR = 2


def _build_parser() -> argparse.ArgumentParser:
    """Build the ``nidhogg`` argument parser with its three subcommands.

    Returns:
        The fully configured parser (``analyze``, ``fetch``, ``monitor``).
    """
    parser = argparse.ArgumentParser(
        prog="nidhogg",
        description="Static analyser of Python packages for malicious URLs.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser(
        "analyze", help="Analyse an already-extracted package directory."
    )
    analyze.add_argument(
        "package_path", type=Path, help="Path to the extracted package."
    )
    analyze.add_argument(
        "--json",
        action="store_true",
        help="Print results as JSON instead of the human-readable format.",
    )
    analyze.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="PATH",
        help="Write JSON results to PATH (implies --json).",
    )
    analyze.add_argument(
        "--benign-domains",
        type=Path,
        default=None,
        metavar="PATH",
        dest="benign_domains",
        help="Path to a text file with benign domains to filter (one per line).",
    )
    analyze.add_argument(
        "--check-ssl",
        action="store_true",
        dest="check_ssl",
        help=(
            "Connect to each HTTPS domain and flag Let's Encrypt certificates "
            "as suspicious (requires network access)."
        ),
    )
    analyze.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging to stderr.",
    )
    analyze.add_argument(
        "--batch",
        action="store_true",
        help=(
            "Treat package_path as a directory of packages and analyse each "
            "subdirectory, printing results per package."
        ),
    )
    analyze.add_argument(
        "--history-dir",
        type=Path,
        default=None,
        metavar="PATH",
        dest="history_dir",
        help="Append each result as JSONL to <PATH>/YYYY-MM-DD.jsonl.",
    )

    fetch = subparsers.add_parser(
        "fetch", help="Download a single package from PyPI and analyse it."
    )
    fetch.add_argument("name", help="PyPI package name to download and analyse.")
    fetch.add_argument(
        "--version",
        default=None,
        metavar="VERSION",
        help="Specific version to download. Defaults to the latest release.",
    )
    fetch.add_argument(
        "--keep-download",
        nargs="?",
        const="",
        default=None,
        metavar="DIR",
        dest="keep_download",
        help=(
            "Keep the downloaded/extracted package instead of deleting it "
            "(optionally moving it to DIR)."
        ),
    )
    fetch.add_argument("--json", action="store_true")
    fetch.add_argument("--output", type=Path, default=None, metavar="PATH")
    fetch.add_argument(
        "--history-dir", type=Path, default=None, metavar="PATH", dest="history_dir"
    )
    fetch.add_argument("--verbose", action="store_true")

    monitor = subparsers.add_parser(
        "monitor", help="Watch PyPI for newly published packages and analyse each."
    )
    monitor.add_argument(
        "--interval",
        type=int,
        default=300,
        metavar="SECONDS",
        help="Seconds to wait between polling iterations.",
    )
    monitor.add_argument(
        "--index-file",
        type=Path,
        default=None,
        metavar="PATH",
        dest="index_file",
        help=(
            "Where to persist the last processed changelog serial. "
            "Defaults to ~/.cache/nidhogg/monitor_state.json."
        ),
    )
    monitor.add_argument(
        "--concurrency",
        type=int,
        default=4,
        metavar="N",
        help="Maximum number of packages to download/analyse concurrently.",
    )
    monitor.add_argument(
        "--keep-download",
        type=Path,
        default=None,
        metavar="DIR",
        dest="keep_download",
        help=(
            "Keep every downloaded/extracted package under DIR instead of deleting it."
        ),
    )
    monitor.add_argument("--json", action="store_true")
    monitor.add_argument(
        "--history-dir", type=Path, default=None, metavar="PATH", dest="history_dir"
    )
    monitor.add_argument("--verbose", action="store_true")

    return parser


def _analyse_one(
    package_path: Path,
    *,
    benign_domains_path: Path | None = None,
    check_ssl: bool = False,
) -> tuple[PackageAnalysis, Verdict] | None:
    """Run the URL-analysis pipeline for a single package directory.

    Args:
        package_path: Directory of the package to analyse.
        benign_domains_path: Optional path to a custom benign domain list.
        check_ssl: When ``True``, query TLS certificates for each HTTPS domain
            and raise confidence for Let's Encrypt issuers.

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

    verdict = classify(analysis)
    return analysis, verdict


def _run_analyze(
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
            and raise confidence for Let's Encrypt issuers.
        history_dir: When provided, append the result document as JSONL under
            this directory.

    Returns:
        ``0`` for a non-malicious package, ``1`` for malicious, ``2`` on error.
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

    return 0 if verdict is Verdict.NOT_MALICIOUS else 1


def _run_batch(
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
            and raise confidence for Let's Encrypt issuers.
        history_dir: When provided, append each package's result document as
            JSONL under this directory.

    Returns:
        ``0`` if no package is malicious, ``1`` if any is, ``2`` if any
        package could not be read.
    """
    if not verbose:
        logger.remove()

    subdirs = sorted(p for p in packages_dir.iterdir() if p.is_dir())
    if not subdirs:
        print(f"No package directories found in {packages_dir}", file=sys.stderr)  # noqa: T201
        return _EXIT_ERROR

    exit_code = 0
    documents: list[dict[str, object]] = []
    use_color = sys.stdout.isatty()
    batch_results: list[tuple[PackageAnalysis, str]] = []

    for pkg_dir in subdirs:
        result = _analyse_one(
            pkg_dir,
            benign_domains_path=benign_domains_path,
            check_ssl=check_ssl,
        )
        if result is None:
            exit_code = _EXIT_ERROR
            continue

        analysis, verdict = result
        if verdict is not Verdict.NOT_MALICIOUS and exit_code != _EXIT_ERROR:
            exit_code = 1

        batch_results.append((analysis, _risk_level(analysis)))

        if history_dir is not None:
            from nidhogg.output.history import append_finding  # noqa: PLC0415

            append_finding(history_dir, build_document(analysis))

        if output is not None or as_json:
            documents.append(build_document(analysis))
        else:
            header = f"=== {pkg_dir.name} ==="
            print(header, flush=True)  # noqa: T201
            print(format_results(analysis, color=use_color))  # noqa: T201

    if output is not None:
        output.write_text(json.dumps(documents, indent=2), encoding="utf-8")
    elif as_json:
        print(json.dumps(documents, indent=2))  # noqa: T201

    if batch_results:
        print(format_batch_summary(batch_results, color=use_color))  # noqa: T201

    return exit_code


def _run_fetch(
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
        ``0`` for a non-malicious package, ``1`` for malicious, ``2`` on error.
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

    return 0 if verdict is Verdict.NOT_MALICIOUS else 1


def _analyse_new_package(
    name: str,
    *,
    keep_download: Path | None,
) -> tuple[PackageAnalysis, Verdict] | None:
    """Download, analyse, and clean up a single monitor-discovered package.

    Args:
        name: PyPI package name to download and analyse.
        keep_download: When provided, keep the extracted package under a
            per-package subdirectory of this directory.

    Returns:
        A ``(PackageAnalysis, Verdict)`` tuple, or ``None`` on read error.
    """
    from nidhogg.fetching.pypi_fetch import fetched_package  # noqa: PLC0415

    keep = keep_download is not None
    keep_dir = keep_download / name if keep_download is not None else None
    with fetched_package(name, keep=keep, keep_dir=keep_dir) as path:
        return _analyse_one(path)


def _run_monitor(
    *,
    interval: int,
    index_file: Path | None,
    concurrency: int,
    keep_download: Path | None,
    as_json: bool,
    history_dir: Path | None,
    verbose: bool,
) -> int:
    """Poll the PyPI changelog for new packages and analyse each one.

    Runs until interrupted with Ctrl+C. Each iteration fetches every
    changelog entry with ``action == "create"`` since the last processed
    serial, downloads and analyses each concurrently, prints results as they
    complete, and persists the new high-water-mark serial.

    Args:
        interval: Seconds to sleep between iterations.
        index_file: Where to persist the last processed serial. Defaults to
            ``~/.cache/nidhogg/monitor_state.json``.
        concurrency: Maximum concurrent downloads/analyses.
        keep_download: When provided, keep each downloaded package under a
            per-package subdirectory of this directory.
        as_json: Print each result as a JSON document instead of the
            human-readable format.
        history_dir: When provided, append each result document as JSONL
            under this directory.
        verbose: Keep loguru logging enabled when True.

    Returns:
        ``0`` when the monitor is stopped cleanly via Ctrl+C.
    """
    if not verbose:
        logger.remove()

    import time  # noqa: PLC0415
    from concurrent.futures import ThreadPoolExecutor, as_completed  # noqa: PLC0415

    from nidhogg.fetching.changelog import ChangelogClient  # noqa: PLC0415
    from nidhogg.fetching.monitor_state import (  # noqa: PLC0415
        MonitorState,
        load_state,
        save_state,
    )

    resolved_index_file = index_file or (
        Path.home() / ".cache" / "nidhogg" / "monitor_state.json"
    )
    client = ChangelogClient()
    state = load_state(resolved_index_file)
    last_serial = state.last_serial if state is not None else client.current_serial()

    try:
        while True:
            current_serial = client.current_serial()
            entries = [e for e in client.entries_since(last_serial) if e.is_new_project]
            logger.info(
                "Monitor: {} new package(s) since serial {}", len(entries), last_serial
            )

            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                futures = {
                    pool.submit(
                        _analyse_new_package,
                        entry.name,
                        keep_download=keep_download,
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
                    analysis, _verdict = result
                    if history_dir is not None:
                        from nidhogg.output.history import (  # noqa: PLC0415
                            append_finding,
                        )

                        append_finding(history_dir, build_document(analysis))
                    if as_json:
                        print(json.dumps(build_document(analysis), indent=2))  # noqa: T201
                    else:
                        print(f"=== {entry.name} ===", flush=True)  # noqa: T201
                        print(format_results(analysis))  # noqa: T201

            last_serial = current_serial
            save_state(resolved_index_file, MonitorState(last_serial=last_serial))
            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("Monitor stopped at serial {}", last_serial)

    return 0


def main() -> None:
    """Entry point for the ``nidhogg`` CLI."""
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "analyze":
        package_path: Path = args.package_path
        if args.batch:
            sys.exit(
                _run_batch(
                    package_path,
                    args.output,
                    as_json=args.json,
                    verbose=args.verbose,
                    benign_domains_path=args.benign_domains,
                    check_ssl=args.check_ssl,
                    history_dir=args.history_dir,
                )
            )
        else:
            sys.exit(
                _run_analyze(
                    package_path,
                    args.output,
                    as_json=args.json,
                    verbose=args.verbose,
                    benign_domains_path=args.benign_domains,
                    check_ssl=args.check_ssl,
                    history_dir=args.history_dir,
                )
            )
    elif args.command == "fetch":
        sys.exit(
            _run_fetch(
                args.name,
                args.version,
                args.output,
                as_json=args.json,
                verbose=args.verbose,
                keep_download=args.keep_download,
                history_dir=args.history_dir,
            )
        )
    else:
        sys.exit(
            _run_monitor(
                interval=args.interval,
                index_file=args.index_file,
                concurrency=args.concurrency,
                keep_download=args.keep_download,
                as_json=args.json,
                history_dir=args.history_dir,
                verbose=args.verbose,
            )
        )


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Replace `tests/test_cli.py`**

```python
"""Tests for cli.py's pipeline wiring."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

from nidhogg.classifier import Verdict
from nidhogg.cli import _build_parser, _run_analyze, _run_fetch, _run_monitor
from nidhogg.core.exceptions import PackageReadError
from nidhogg.core.models import PackageAnalysis
from nidhogg.fetching.changelog import ChangelogEntry
from nidhogg.fetching.monitor_state import MonitorState, load_state, save_state


def test_build_parser_history_dir_defaults_none():
    parser = _build_parser()
    args = parser.parse_args(["analyze", "some/path"])
    assert args.history_dir is None


def test_build_parser_history_dir_accepts_path():
    parser = _build_parser()
    args = parser.parse_args(
        ["analyze", "some/path", "--history-dir", "/tmp/hist"]  # noqa: S108
    )
    assert str(args.history_dir) == "/tmp/hist"  # noqa: S108


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
    assert list(tmp_path.glob("*.jsonl")) == []


def test_run_fetch_analyses_downloaded_package(tmp_path: Path):
    extracted = tmp_path / "extracted"
    (extracted / "pkg").mkdir(parents=True)
    (extracted / "pkg" / "module.py").write_text("x = 1", encoding="utf-8")

    @contextmanager
    def _fake_fetched_package(
        name,  # noqa: ARG001
        version=None,  # noqa: ARG001
        *,
        keep=False,  # noqa: ARG001
        keep_dir=None,  # noqa: ARG001
    ):
        yield extracted

    with patch("nidhogg.fetching.pypi_fetch.fetched_package", _fake_fetched_package):
        exit_code = _run_fetch(
            "somepkg",
            None,
            None,
            as_json=False,
            verbose=False,
            keep_download=None,
            history_dir=None,
        )
    assert exit_code == 0


def test_run_fetch_returns_error_on_download_failure():
    with patch(
        "nidhogg.fetching.pypi_fetch.fetched_package",
        side_effect=PackageReadError("boom"),
    ):
        exit_code = _run_fetch(
            "somepkg",
            None,
            None,
            as_json=False,
            verbose=False,
            keep_download=None,
            history_dir=None,
        )
    assert exit_code == 2


def test_run_fetch_writes_history(tmp_path: Path):
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    history_dir = tmp_path / "history"

    @contextmanager
    def _fake_fetched_package(
        name,  # noqa: ARG001
        version=None,  # noqa: ARG001
        *,
        keep=False,  # noqa: ARG001
        keep_dir=None,  # noqa: ARG001
    ):
        yield extracted

    with patch("nidhogg.fetching.pypi_fetch.fetched_package", _fake_fetched_package):
        _run_fetch(
            "somepkg",
            None,
            None,
            as_json=False,
            verbose=False,
            keep_download=None,
            history_dir=history_dir,
        )
    assert len(list(history_dir.glob("*.jsonl"))) == 1


def test_run_monitor_processes_one_batch_then_stops(tmp_path: Path):
    """KeyboardInterrupt after the first iteration exits the loop cleanly."""
    index_file = tmp_path / "state.json"
    fake_client = MagicMock()
    fake_client.current_serial.side_effect = [100, 100]
    fake_client.entries_since.return_value = [
        ChangelogEntry(
            name="newpkg", version="", timestamp=1, action="create", serial=99
        )
    ]

    fake_analysis = PackageAnalysis(name="newpkg", path=tmp_path)

    def _fake_analyse_new_package(name, **kwargs):  # noqa: ARG001
        return fake_analysis, Verdict.NOT_MALICIOUS

    def _fake_sleep(seconds):  # noqa: ARG001
        raise KeyboardInterrupt

    with (
        patch("nidhogg.fetching.changelog.ChangelogClient", return_value=fake_client),
        patch("nidhogg.cli._analyse_new_package", _fake_analyse_new_package),
        patch("time.sleep", _fake_sleep),
    ):
        exit_code = _run_monitor(
            interval=0,
            index_file=index_file,
            concurrency=2,
            keep_download=None,
            as_json=False,
            history_dir=None,
            verbose=False,
        )

    assert exit_code == 0
    state = load_state(index_file)
    assert state == MonitorState(last_serial=100)


def test_run_monitor_resumes_from_persisted_serial(tmp_path: Path):
    index_file = tmp_path / "state.json"
    save_state(index_file, MonitorState(last_serial=500))

    fake_client = MagicMock()
    fake_client.current_serial.return_value = 500
    fake_client.entries_since.return_value = []

    def _fake_sleep(seconds):  # noqa: ARG001
        raise KeyboardInterrupt

    with (
        patch("nidhogg.fetching.changelog.ChangelogClient", return_value=fake_client),
        patch("time.sleep", _fake_sleep),
    ):
        _run_monitor(
            interval=0,
            index_file=index_file,
            concurrency=2,
            keep_download=None,
            as_json=False,
            history_dir=None,
            verbose=False,
        )

    fake_client.entries_since.assert_called_once_with(500)


def test_run_monitor_continues_after_one_package_fails(tmp_path: Path):
    index_file = tmp_path / "state.json"
    fake_client = MagicMock()
    fake_client.current_serial.return_value = 10
    fake_client.entries_since.return_value = [
        ChangelogEntry(
            name="badpkg", version="", timestamp=1, action="create", serial=1
        ),
        ChangelogEntry(
            name="goodpkg", version="", timestamp=2, action="create", serial=2
        ),
    ]

    fake_analysis = PackageAnalysis(name="goodpkg", path=tmp_path)

    def _fake_analyse_new_package(name, **kwargs):  # noqa: ARG001
        if name == "badpkg":
            raise PackageReadError("network error")
        return fake_analysis, Verdict.NOT_MALICIOUS

    def _fake_sleep(seconds):  # noqa: ARG001
        raise KeyboardInterrupt

    with (
        patch("nidhogg.fetching.changelog.ChangelogClient", return_value=fake_client),
        patch("nidhogg.cli._analyse_new_package", _fake_analyse_new_package),
        patch("time.sleep", _fake_sleep),
    ):
        exit_code = _run_monitor(
            interval=0,
            index_file=index_file,
            concurrency=2,
            keep_download=None,
            as_json=False,
            history_dir=None,
            verbose=False,
        )

    # The monitor itself always exits 0 (stopped via Ctrl+C); the important
    # assertion is that it reached save_state despite badpkg failing.
    assert exit_code == 0
    assert load_state(index_file) == MonitorState(last_serial=10)
```

- [ ] **Step 3: Run the tests**

Run: `uv run pytest tests/test_cli.py -v`
Expected: All tests PASS.

- [ ] **Step 4: Verify no leftover typosquat/pattern references anywhere**

Run: `grep -rn "typosquat\|Typosquat\|pattern_findings\|PatternCategory" nidhogg/ tests/ -i`
Expected: no output (empty) — this confirms Task 6's deletions are now fully unreferenced.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/cli.py tests/test_cli.py
git commit -m "$(cat <<'EOF'
refactor(cli)!: drop typosquat/pattern flags and dead check_urls toggle

Removes --no-check-typosquat, --no-typosquat-intel, --update-top-packages,
and --no-check-urls (the last one only existed to allow a typosquat-only
run, which is no longer possible). analyze/fetch/monitor now always run
the URL pipeline.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: Update the integration test

**Files:**
- Modify: `tests/test_integration.py`

**Interfaces:**
- Consumes: `analyze_package`, `aggregate`, `classify`/`Verdict`, `write_results`, `_run_analyze`, `main` — all from Tasks 4/3/7/8, unchanged signatures for this test's purposes.

- [ ] **Step 1: Replace `tests/test_integration.py`**

```python
"""Integration tests: full pipeline over tests/fixtures/pkg_malicioso/."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from nidhogg.analysis.aggregator import aggregate
from nidhogg.analysis.walker import analyze_package
from nidhogg.classifier import Verdict, classify
from nidhogg.output.writer import write_results

PKG = Path(__file__).parent / "fixtures" / "pkg_malicioso"


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def test_pipeline_produces_findings():
    analysis = analyze_package(PKG)
    analysis.findings = aggregate(analysis.findings)
    assert len(analysis.findings) > 0


def test_pipeline_detects_dynamic_execution():
    analysis = analyze_package(PKG)
    assert analysis.uses_dynamic_execution is True


def test_pipeline_finds_c2_url():
    analysis = analyze_package(PKG)
    analysis.findings = aggregate(analysis.findings)
    urls = {f.value for f in analysis.findings}
    assert any("c2.evil.example.com" in url for url in urls)


def test_pipeline_finds_beacon_url():
    analysis = analyze_package(PKG)
    analysis.findings = aggregate(analysis.findings)
    urls = {f.value for f in analysis.findings}
    assert any("beacon" in url for url in urls)


def test_pipeline_verdict_is_malicious():
    analysis = analyze_package(PKG)
    analysis.findings = aggregate(analysis.findings)
    assert classify(analysis) is Verdict.MALICIOUS


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def test_pipeline_output_structure(tmp_path: Path):
    analysis = analyze_package(PKG)
    analysis.findings = aggregate(analysis.findings)
    out = tmp_path / "results.json"
    write_results(analysis, out)
    data = json.loads(out.read_text())
    assert "package" in data
    assert "summary" in data
    assert "findings" in data


def test_pipeline_output_risk_malicious(tmp_path: Path):
    analysis = analyze_package(PKG)
    analysis.findings = aggregate(analysis.findings)
    classify(analysis)
    out = tmp_path / "results.json"
    write_results(analysis, out)
    data = json.loads(out.read_text())
    assert data["summary"]["risk_level"] == "malicious"


def test_pipeline_output_dynamic_execution_flagged(tmp_path: Path):
    analysis = analyze_package(PKG)
    out = tmp_path / "results.json"
    write_results(analysis, out)
    data = json.loads(out.read_text())
    assert data["summary"]["uses_dynamic_execution"] is True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_exits_nonzero_for_malicious_package():
    from nidhogg.cli import _run_analyze

    code = _run_analyze(PKG, None, as_json=False, verbose=False)
    assert code != 0


def test_cli_prints_json_to_stdout(capsys: pytest.CaptureFixture[str]):
    from nidhogg.cli import _run_analyze

    _run_analyze(PKG, None, as_json=True, verbose=False)
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "findings" in data


def test_cli_pretty_output_to_stdout(capsys: pytest.CaptureFixture[str]):
    from nidhogg.cli import _run_analyze

    _run_analyze(PKG, None, as_json=False, verbose=False)
    captured = capsys.readouterr()
    assert "MALICIOUS" in captured.out
    assert "c2.evil.example.com" in captured.out


def test_cli_writes_file_when_output_given(tmp_path: Path):
    from nidhogg.cli import _run_analyze

    out = tmp_path / "results.json"
    _run_analyze(PKG, out, as_json=False, verbose=False)
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["summary"]["risk_level"] == "malicious"


def test_cli_main_analyze_command(tmp_path: Path):
    from nidhogg.cli import main

    out = tmp_path / "results.json"
    with (
        patch.object(
            sys, "argv", ["nidhogg", "analyze", str(PKG), "--output", str(out)]
        ),
        pytest.raises(SystemExit) as exc_info,
    ):
        main()
    assert exc_info.value.code != 0
    assert out.exists()


def test_cli_exits_zero_for_clean_package(tmp_path: Path):
    from nidhogg.cli import _run_analyze

    clean = tmp_path / "clean_pkg"
    clean.mkdir()
    (clean / "hello.py").write_text('print("hello world")\n', encoding="utf-8")
    code = _run_analyze(clean, None, as_json=False, verbose=False)
    assert code == 0


def test_cli_error_on_missing_path(tmp_path: Path):
    from nidhogg.cli import _run_analyze

    code = _run_analyze(tmp_path / "nonexistent", None, as_json=False, verbose=False)
    assert code == 2
```

- [ ] **Step 2: Run the tests**

Run: `uv run pytest tests/test_integration.py -v`
Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/test_integration.py
git commit -m "$(cat <<'EOF'
test(integration)!: drop typosquat e2e test, update to binary verdict

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: Update README.md

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace `README.md`**

```markdown
# Nidhogg

Analizador estático de paquetes Python centrado en la detección y clasificación de URLs maliciosas.
Recibe carpetas ya extraídas de paquetes PyPI, extrae toda URL candidata (literal, ofuscada, o construida dinámicamente) y produce un veredicto binario: `malicious` / `not_malicious`.

## Requisitos

- Python 3.14+
- [uv](https://docs.astral.sh/uv/)

## Instalación

```bash
uv sync
```

## Uso

```bash
# Analizar un paquete
uv run nidhogg analyze <ruta_paquete>

# Con output JSON a fichero
uv run nidhogg analyze <ruta_paquete> --output results.json

# Lista de dominios benignos personalizada
uv run nidhogg analyze <ruta_paquete> --benign-domains my_domains.txt

# Enriquecimiento TLS (requiere red)
uv run nidhogg analyze <ruta_paquete> --check-ssl

# Análisis en lote
uv run nidhogg analyze <directorio_de_paquetes> --batch --output results.json

# Logs detallados
uv run nidhogg analyze <ruta_paquete> --verbose

# Descargar y analizar un paquete puntual de PyPI
uv run nidhogg fetch requests

# Versión concreta, sin borrar la descarga
uv run nidhogg fetch requests --version 2.31.0 --keep-download ./descargas

# Vigilar altas nuevas en PyPI y analizar cada una
uv run nidhogg monitor --interval 60 --concurrency 8
```

### Opciones disponibles — `analyze`

| Opción | Descripción |
|--------|-------------|
| `--json` | Salida JSON por stdout |
| `--output PATH` | Escribe JSON en fichero |
| `--benign-domains PATH` | Lista de dominios benignos personalizada |
| `--check-ssl` | Verifica certificados TLS (requiere red) |
| `--verbose` | Activa logs de depuración |
| `--batch` | Trata la entrada como directorio de paquetes |
| `--history-dir PATH` | Añade cada resultado como JSONL en `<PATH>/YYYY-MM-DD.jsonl` |

### `fetch` — descarga puntual bajo demanda

Descarga un paquete concreto de PyPI (`nidhogg/fetching/pypi_fetch.py`), lo
extrae a un directorio temporal y ejecuta el mismo pipeline de análisis.
Mecanismo de descubrimiento propio e independiente del downloader externo
del flujo batch.

| Opción | Descripción |
|--------|-------------|
| `name` | Nombre del paquete en PyPI (posicional) |
| `--version VERSION` | Versión concreta; por defecto la última release |
| `--keep-download [DIR]` | Conserva la descarga/extracción en lugar de borrarla |
| `--json`, `--output PATH`, `--history-dir PATH`, `--verbose` | Igual que en `analyze` |

### `monitor` — vigilancia de altas nuevas en PyPI

Sondea el changelog XML-RPC de PyPI (`nidhogg/fetching/changelog.py`) en
bucle, descarga y analiza cada paquete nuevo publicado, y persiste el
último serial procesado (`nidhogg/fetching/monitor_state.py`) para poder
reanudar sin reprocesar altas ya vistas.

| Opción | Descripción |
|--------|-------------|
| `--interval SECONDS` | Segundos entre iteraciones de sondeo (por defecto 300) |
| `--index-file PATH` | Fichero de persistencia del último serial (por defecto `~/.cache/nidhogg/monitor_state.json`) |
| `--concurrency N` | Nº máximo de paquetes a descargar/analizar en paralelo (por defecto 4) |
| `--keep-download DIR` | Conserva todas las descargas/extracciones bajo DIR |
| `--json`, `--history-dir PATH`, `--verbose` | Igual que en `analyze` |

### Códigos de salida

| Código | Significado |
|--------|-------------|
| `0` | Paquete `NOT_MALICIOUS` |
| `1` | Paquete `MALICIOUS` |
| `2` | Error (ruta inválida, fallo de lectura, etc.) |

## Pipeline

```
walker → [layer1_regex + layer2_ast] → aggregator → enrichment(ssl_cert) → classifier → output
```

Las dos capas de análisis se ejecutan en paralelo sobre cada fichero `.py`. El resultado se agrega, enriquece y clasifica para producir un veredicto final.

### Layer 1 — Regex

Extracción rápida sobre texto plano:

- URLs con esquema (`http`, `https`, `ftp`, `ws`, `wss`)
- IPv4 en contexto de red (llamadas a `connect`, `urlopen`, `requests`, etc.)
- IPv6 en forma completa y abreviada
- Filtrado automático de IPs privadas (RFC 1918 + loopback)

Confianza base: `0.50–0.65`.

### Layer 2 — AST

Resolución estática de URLs ofuscadas mediante análisis del árbol sintáctico:

- **Constant folding:** strings literales que contienen URL
- **Concatenación binaria:** `"http://" + "evil.com"` → resuelto a URL completa
- **Base64:** `base64.b64decode(Constant)` → decodificado y extraído
- **F-strings:** `ast.JoinedStr` con partes resolvibles
- **Scope tracking:** seguimiento de variables asignadas antes del punto de uso
- **Detección de ejecución dinámica:** `eval` / `exec` → flag `uses_dynamic_execution = True` (fuerza veredicto `MALICIOUS`, ya que la URL construida no puede resolverse estáticamente)

Confianza base: `0.75–0.95`.

### Aggregator

- Deduplicación: conserva el finding de mayor confianza para cada URL única
- Normalización: dominio en minúsculas, eliminación de fragmentos y trailing slashes
- Filtrado de dominios benignos: lista configurable con soporte de wildcard (`pypi.org` cubre `files.pypi.org`)
- Clasificación de dominios: categorización de amenaza para cada URL restante
- Boost de confianza: +0.20 para `EXFILTRATION` / `MALWARE_HOSTING`, +0.10 para otras amenazas (máximo 0.99)

### Clasificación de dominios

Categorías de amenaza evaluadas en orden:

| Categoría | Descripción | Ejemplos |
|-----------|-------------|---------|
| `RAW_IP` | IP pública directa | `185.220.101.x` |
| `SHORTENER` | Acortadores de URL | `bit.ly`, `tinyurl.com`, `t.co` |
| `TUNNELING` | Túneles de exposición | `ngrok.io`, `workers.dev`, `serveo.net` |
| `EXFILTRATION` | Destinos de exfiltración conocidos | `discord.com`, `t.me`, `pastebin.com`, `webhook.site` |
| `IP_RECON` | Reconocimiento de IP pública | `ipinfo.io`, `ifconfig.me`, `api.ipify.org` |
| `MALWARE_HOSTING` | Hosting de ficheros anónimos | `files.catbox.moe`, `gofile.io` |
| `SUSPICIOUS_TLD` | TLDs de riesgo | `.tk`, `.ml`, `.zip`, `.xyz`, `.pw` |

Un dominio `EXFILTRATION`/`MALWARE_HOSTING` fuerza veredicto `MALICIOUS` independientemente de la confianza del finding.

### Enriquecimiento

**SSL/TLS (`--check-ssl`):** Conecta al puerto 443 de cada dominio HTTPS y extrae el emisor del certificado. Si es Let's Encrypt, sube la confianza del finding en +0.05.

### Historial

Con `--history-dir PATH`, cada resultado se añade en formato JSONL a `<PATH>/YYYY-MM-DD.jsonl` (`nidhogg/output/history.py`). Escritura append-only; los fallos de disco/permisos se registran como warning y nunca interrumpen el análisis.

## Scoring

El score global cuantifica el riesgo del paquete en el rango `[0.0, 0.99]`:

```
score = max(confianza de todos los findings de URL, o 0.0 si no hay ninguno)
score = max(score, malicious_url)  si hay ejecución dinámica
score = max(score, domain_floor)   si hay dominio EXFILTRATION/MALWARE_HOSTING
score = min(score, 0.99)
```

El score siempre queda por encima de `thresholds.malicious_url` exactamente cuando el veredicto es `MALICIOUS` — son la misma condición expresada dos veces (una como número, otra como enum), así que `risk_level` en la salida se deriva directamente del score.

Los pesos y umbrales se configuran en `nidhogg/data/scoring.toml`:

| Parámetro | Valor por defecto | Descripción |
|-----------|-------------------|-------------|
| `thresholds.malicious_url` | 0.85 | Confianza mínima de un finding de URL para veredicto `MALICIOUS` |
| `domain_boosts.high` | 0.20 | Boost de confianza para `EXFILTRATION`/`MALWARE_HOSTING` |
| `domain_boosts.normal` | 0.10 | Boost de confianza para el resto de amenazas de dominio |
| `ssl.confidence_bump` | 0.05 | Boost de confianza por certificado Let's Encrypt |
| `score.domain_floor` | 0.90 | Score mínimo si hay dominio `EXFILTRATION`/`MALWARE_HOSTING` |

### Veredicto final

El clasificador asigna el veredicto en orden de prioridad:

1. Sin findings de URL y sin ejecución dinámica → `NOT_MALICIOUS`
2. Dominio `EXFILTRATION` / `MALWARE_HOSTING` → `MALICIOUS`
3. Ejecución dinámica (`eval`/`exec`) → `MALICIOUS`
4. URL con confianza ≥ `thresholds.malicious_url` → `MALICIOUS`
5. En cualquier otro caso → `NOT_MALICIOUS`

## Tests

```bash
uv run pytest
```

| Fichero | Qué verifica |
|---------|--------------|
| `test_models.py` | Instanciación y serialización de dataclasses |
| `test_walker.py` | Recorrido de paquetes y recolección de ficheros |
| `test_layer1_regex.py` | Detección de URLs e IPs por regex |
| `test_layer2_ast.py` | Constant folding, base64, f-strings, scope tracking |
| `test_aggregator.py` | Deduplicación, normalización, filtrado de dominios |
| `test_domain_classifier.py` | Categorización de amenazas por dominio |
| `test_ssl_cert.py` | Verificación de certificados TLS (mockeado) |
| `test_scoring.py` | Cálculo del score global |
| `test_classifier.py` | Veredicto binario `MALICIOUS`/`NOT_MALICIOUS` |
| `test_output_writer.py` | Serialización JSON y salida por terminal |
| `test_cli.py` | Wiring de `analyze`/`fetch`/`monitor` |
| `test_integration.py` | Pipeline completo end-to-end |
| `test_pypi_fetch.py`, `test_changelog.py`, `test_monitor_state.py` | Descubrimiento (`fetching/`) |
| `test_history.py` | Historial JSONL append-only |

Los fixtures de código están en `tests/fixtures/` como ficheros `.py` reales organizados por escenario:

- `pkg_basic/` — URLs literales, concatenación, ejecución dinámica
- `pkg_obfuscated/` — Base64, f-strings, scope tracking
- `pkg_malicioso/` — Combinación realista de URLs + ejecución dinámica

### Calidad de código

```bash
uv run ruff check       # linting
uv run ruff format      # formateo
uv run mypy             # type checking estricto
```

## Arquitectura

```
nidhogg/
├── core/
│   ├── models.py               # Dataclasses compartidas (PackageAnalysis, UrlFinding, etc.)
│   └── exceptions.py           # Excepciones propias del proyecto
├── analysis/
│   ├── walker.py               # Entrada principal: orquesta el análisis de un paquete
│   ├── layer1_regex.py         # Capa 1: extracción por regex sobre texto plano
│   ├── layer2_ast.py           # Capa 2: constant folding, base64, f-strings, scope tracking
│   ├── aggregator.py           # Deduplicación, normalización y clasificación de dominios
│   └── domain_classifier.py    # Categorización de amenaza por dominio/IP
├── enrichment/
│   └── ssl_cert.py             # Verificación de certificados TLS
├── fetching/
│   ├── pypi_fetch.py           # Descarga + extracción segura de un paquete puntual de PyPI
│   ├── changelog.py            # Cliente del changelog XML-RPC de PyPI (altas nuevas)
│   └── monitor_state.py        # Persistencia del último serial procesado por `monitor`
├── output/
│   ├── writer.py               # Serialización JSON y salida por terminal
│   └── history.py              # Historial JSONL append-only (--history-dir)
├── scoring.py                  # Motor de scoring global
├── classifier.py               # Asignación de veredicto final
├── cli.py                      # Punto de entrada CLI: analyze / fetch / monitor
└── data/
    ├── scoring.toml            # Pesos y umbrales configurables
    ├── suspicious_domains.toml # Dominios amenaza por categoría
    └── benign_domains.txt      # ~100 dominios legítimos
```
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "$(cat <<'EOF'
docs: rewrite README for URL-only Nidhogg

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 11: Full-suite verification

**Files:** none (verification only).

- [ ] **Step 1: Confirm no dependency cleanup is needed in `pyproject.toml`**

`pyproject.toml`'s only runtime dependency is `loguru>=0.7`; the typosquat/RDAP
code used the standard-library `urllib.request`, not a third-party HTTP
client, so there is nothing to `uv remove`. Run this to double-check before
moving on:

Run: `grep -n "dependencies" -A 5 pyproject.toml`
Expected: only `"loguru>=0.7"` listed — no edit needed.

- [ ] **Step 2: Run the full test suite**

Run: `uv run pytest -v`
Expected: All tests PASS, zero collection errors.

- [ ] **Step 3: Run ruff**

Run: `uv run ruff check`
Expected: No errors. If any appear in files touched by this plan, fix them directly (e.g. unused imports left over from a deletion).

Run: `uv run ruff format --check`
Expected: No reformatting needed. If it reports files, run `uv run ruff format` and re-check.

- [ ] **Step 4: Run mypy**

Run: `uv run mypy`
Expected: No errors (`Success: no issues found`).

- [ ] **Step 5: Manual smoke test against a real fixture**

Run: `uv run nidhogg analyze tests/fixtures/pkg_malicioso`
Expected: Human-readable output showing `risk MALICIOUS`, a non-empty `URLs:` section, `dynamic yes`, and the process exits with code `1` (check with `echo $?`).

Run: `uv run nidhogg analyze tests/fixtures/pkg_basic --json`
Expected: Valid JSON on stdout with `"risk_level"` set to either `"malicious"` or `"clean"` and no `pattern_findings`/`typosquat` keys anywhere in the document.

- [ ] **Step 6: Commit if Steps 3–4 required fixes**

```bash
git add -A
git commit -m "$(cat <<'EOF'
fix: address ruff/mypy findings from URL-only simplification

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

Skip this step if Steps 3–4 reported no issues.
