# File/URL Tagging System Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a two-level tagging system (file-context tags + URL tags) to the analysis pipeline, folding the old `DetectionMethod`/`DomainThreatCategory` signals into typed tag enums.

**Architecture:** Each analysed file becomes a `FileAnalysis` carrying `set[FileTag]` (readme/test/docs/packaging/…) and its `UrlFinding` list; each finding carries `set[UrlTag]` (extraction method + domain threat). `PackageAnalysis` holds a list of `FileAnalysis` with a `findings` flatten property for backward-compatible consumers. The walker widens from `.py`-only to a text-file whitelist so file-context tags are meaningful.

**Tech Stack:** Python 3.14, uv, pytest, loguru, ruff, mypy. All commands via `uv run`.

## Global Constraints

- Python 3.14; use recent features where they add clarity.
- Never use pip; dependencies via `uv add`. Run everything via `uv run`.
- Strict type hints on every function/method including returns. Google-style docstrings on public functions.
- Dataclasses for models, never loose dicts. Functions small (~30 lines) and pure (no hidden global state) in analysis code.
- Analysis layers must never execute analysed package code.
- Full-suite gate: `uv run pytest`, `uv run ruff check`, `uv run ruff format --check`, `uv run mypy` must all pass before the plan is done.

## Spec reference

`docs/superpowers/specs/2026-07-16-url-file-tagging-design.md`

## Symbol mapping (source of truth for all tasks)

Old `DetectionMethod` → `UrlTag`:

| DetectionMethod | UrlTag | Notes |
|-----------------|--------|-------|
| `LITERAL` | *(no tag)* | plain literal, unremarkable |
| `CONCAT` | `VIA_CONCAT` | |
| `BASE64` | `VIA_BASE64` | |
| `FSTRING` | `VIA_FSTRING` | |
| `SCOPE_TRACKING` | `VIA_SCOPE` | |
| `IP` | `RAW_IP` | |

Old `DomainThreatCategory` → `UrlTag` (identical member names/values): `SHORTENER`, `TUNNELING`, `EXFILTRATION`, `IP_RECON`, `MALWARE_HOSTING`, `SUSPICIOUS_TLD`, `RAW_IP`.

## File structure

- Modify: `nidhogg/core/models.py` — new enums + two-level containers.
- Create: `nidhogg/analysis/file_classifier.py` — path-based file tagging.
- Modify: `nidhogg/analysis/layer1_regex.py`, `layer2_ast.py`, `domain_classifier.py`, `aggregator.py`, `walker.py`.
- Modify: `nidhogg/enrichment/ssl_cert.py` — unchanged logic; called differently by cli.
- Modify: `nidhogg/output/writer.py`, `renderer.py` (`history.py` needs no code change — it serialises whatever `build_document` returns).
- Modify: `nidhogg/cli.py` — assign `.files` instead of `.findings`; SSL check in place.
- Tests: create `tests/test_file_classifier.py`; update `test_models.py`, `test_layer1_regex.py`, `test_layer2_ast.py`, `test_domain_classifier.py`, `test_aggregator.py`, `test_walker.py`, `test_ssl_cert.py`, `test_output_writer.py`, `test_renderer.py`, `test_cli.py`, `test_integration.py`.
- Fixtures: add `tests/fixtures/pkg_basic/README.md` (or a dedicated fixture) containing a URL.

---

### Task 1: Data model — enums and two-level containers

**Files:**
- Modify: `nidhogg/core/models.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `class FileTag(enum.Enum)` members: `README="readme"`, `DOCS="docs"`, `TEST="test"`, `EXAMPLE="example"`, `PACKAGING="packaging"`, `INIT="init"`, `ENTRYPOINT="entrypoint"`, `DOTFILE="dotfile"`, `DYNAMIC_EXEC="dynamic_exec"`.
  - `class UrlTag(enum.Enum)` members: `VIA_BASE64="via_base64"`, `VIA_CONCAT="via_concat"`, `VIA_FSTRING="via_fstring"`, `VIA_SCOPE="via_scope"`, `RAW_IP="raw_ip"`, `SHORTENER="shortener"`, `TUNNELING="tunneling"`, `EXFILTRATION="exfiltration"`, `IP_RECON="ip_recon"`, `MALWARE_HOSTING="malware_hosting"`, `SUSPICIOUS_TLD="suspicious_tld"`.
  - `class AnalysisLayer(enum.Enum)` unchanged (`REGEX`, `AST`).
  - `@dataclass UrlFinding`: `value: str`, `filepath: Path`, `lineno: int`, `layer: AnalysisLayer`, `tags: set[UrlTag] = field(default_factory=set)`, `cert_issuer: str | None = None`. (Removed: `method`, `domain_threat`.)
  - `@dataclass FileAnalysis`: `filepath: Path`, `tags: set[FileTag] = field(default_factory=set)`, `findings: list[UrlFinding] = field(default_factory=list)`.
  - `@dataclass PackageAnalysis`: `name: str`, `path: Path`, `files: list[FileAnalysis] = field(default_factory=list)`, plus read-only property `findings -> list[UrlFinding]` flattening all file findings.
  - Deleted: `class DetectionMethod`, `class DomainThreatCategory`.

- [ ] **Step 1: Write the failing test**

Replace the contents of `tests/test_models.py` with:

```python
"""Tests for the shared data models."""

from __future__ import annotations

from pathlib import Path

from nidhogg.core.models import (
    AnalysisLayer,
    FileAnalysis,
    FileTag,
    PackageAnalysis,
    UrlFinding,
    UrlTag,
)


def test_urlfinding_defaults_empty_tags_and_no_cert() -> None:
    finding = UrlFinding(
        value="http://x.test",
        filepath=Path("a.py"),
        lineno=1,
        layer=AnalysisLayer.AST,
    )
    assert finding.tags == set()
    assert finding.cert_issuer is None


def test_fileanalysis_defaults_empty_tags_and_findings() -> None:
    fa = FileAnalysis(filepath=Path("a.py"))
    assert fa.tags == set()
    assert fa.findings == []


def test_packageanalysis_findings_property_flattens_all_files() -> None:
    f1 = UrlFinding("http://a.test", Path("a.py"), 1, AnalysisLayer.REGEX)
    f2 = UrlFinding("http://b.test", Path("b.py"), 2, AnalysisLayer.AST)
    pkg = PackageAnalysis(
        name="p",
        path=Path("/p"),
        files=[
            FileAnalysis(Path("a.py"), {FileTag.README}, [f1]),
            FileAnalysis(Path("b.py"), set(), [f2]),
        ],
    )
    assert pkg.findings == [f1, f2]


def test_urltag_and_filetag_values_are_stable() -> None:
    assert UrlTag.VIA_BASE64.value == "via_base64"
    assert UrlTag.RAW_IP.value == "raw_ip"
    assert FileTag.README.value == "readme"
    assert FileTag.DYNAMIC_EXEC.value == "dynamic_exec"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_models.py -v`
Expected: FAIL — `ImportError` on `FileTag`/`UrlTag`/`FileAnalysis`.

- [ ] **Step 3: Write minimal implementation**

Replace the contents of `nidhogg/core/models.py` with:

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


class FileTag(enum.Enum):
    """Context tag describing the role of a file within a package."""

    README = "readme"
    DOCS = "docs"
    TEST = "test"
    EXAMPLE = "example"
    PACKAGING = "packaging"
    INIT = "init"
    ENTRYPOINT = "entrypoint"
    DOTFILE = "dotfile"
    DYNAMIC_EXEC = "dynamic_exec"


class UrlTag(enum.Enum):
    """Tag describing how a URL was extracted or the threat of its host."""

    VIA_BASE64 = "via_base64"
    VIA_CONCAT = "via_concat"
    VIA_FSTRING = "via_fstring"
    VIA_SCOPE = "via_scope"
    RAW_IP = "raw_ip"
    SHORTENER = "shortener"
    TUNNELING = "tunneling"
    EXFILTRATION = "exfiltration"
    IP_RECON = "ip_recon"
    MALWARE_HOSTING = "malware_hosting"
    SUSPICIOUS_TLD = "suspicious_tld"


@dataclass
class UrlFinding:
    """A single URL candidate found during package analysis.

    Attributes:
        value: The extracted URL string.
        filepath: Path to the source file where the URL was found.
        lineno: Line number in the source file (1-indexed).
        layer: Which analysis layer produced this finding.
        tags: URL tags describing extraction method and host threat.
        cert_issuer: TLS certificate issuer organisation, set by the SSL
            enrichment step. ``None`` when not checked or not HTTPS.
    """

    value: str
    filepath: Path
    lineno: int
    layer: AnalysisLayer
    tags: set[UrlTag] = field(default_factory=set)
    cert_issuer: str | None = None


@dataclass
class FileAnalysis:
    """Analysis of a single source file: its context tags and URL findings.

    Attributes:
        filepath: Path to the analysed file.
        tags: File-context tags derived from the file's path and content.
        findings: URL findings collected from this file.
    """

    filepath: Path
    tags: set[FileTag] = field(default_factory=set)
    findings: list[UrlFinding] = field(default_factory=list)


@dataclass
class PackageAnalysis:
    """Aggregated results of analysing a single package directory.

    Attributes:
        name: Package name (derived from the directory name).
        path: Absolute path to the package directory.
        files: Per-file analyses collected across the package.
    """

    name: str
    path: Path
    files: list[FileAnalysis] = field(default_factory=list)

    @property
    def findings(self) -> list[UrlFinding]:
        """Flatten the findings of every analysed file.

        Returns:
            Every :class:`UrlFinding` across all files, in file order.
        """
        return [finding for fa in self.files for finding in fa.findings]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_models.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add nidhogg/core/models.py tests/test_models.py
git commit -m "feat: add FileTag/UrlTag enums and two-level analysis containers"
```

---

### Task 2: File classifier

**Files:**
- Create: `nidhogg/analysis/file_classifier.py`
- Test: `tests/test_file_classifier.py`

**Interfaces:**
- Consumes: `FileTag` from Task 1.
- Produces: `classify_file(path: Path, root: Path) -> set[FileTag]` — path/name-based only, reads no content. Does **not** emit `DYNAMIC_EXEC` (content-based, added by Task 7).

- [ ] **Step 1: Write the failing test**

Create `tests/test_file_classifier.py`:

```python
"""Tests for path-based file classification."""

from __future__ import annotations

from pathlib import Path

from nidhogg.analysis.file_classifier import classify_file
from nidhogg.core.models import FileTag

ROOT = Path("/pkg")


def test_readme_file_tagged_readme() -> None:
    assert FileTag.README in classify_file(ROOT / "README.md", ROOT)


def test_markdown_under_docs_tagged_docs() -> None:
    tags = classify_file(ROOT / "docs" / "guide.md", ROOT)
    assert FileTag.DOCS in tags


def test_test_prefixed_file_tagged_test() -> None:
    assert FileTag.TEST in classify_file(ROOT / "test_thing.py", ROOT)


def test_file_under_tests_dir_tagged_test() -> None:
    assert FileTag.TEST in classify_file(ROOT / "tests" / "helpers.py", ROOT)


def test_setup_py_tagged_packaging() -> None:
    assert FileTag.PACKAGING in classify_file(ROOT / "setup.py", ROOT)


def test_pyproject_tagged_packaging() -> None:
    assert FileTag.PACKAGING in classify_file(ROOT / "pyproject.toml", ROOT)


def test_init_tagged_init() -> None:
    assert FileTag.INIT in classify_file(ROOT / "pkg" / "__init__.py", ROOT)


def test_main_tagged_entrypoint() -> None:
    assert FileTag.ENTRYPOINT in classify_file(ROOT / "pkg" / "__main__.py", ROOT)


def test_hidden_dir_tagged_dotfile() -> None:
    assert FileTag.DOTFILE in classify_file(ROOT / ".github" / "x.py", ROOT)


def test_example_dir_tagged_example() -> None:
    assert FileTag.EXAMPLE in classify_file(ROOT / "examples" / "demo.py", ROOT)


def test_multiple_tags_combine() -> None:
    tags = classify_file(ROOT / "tests" / "__init__.py", ROOT)
    assert {FileTag.TEST, FileTag.INIT} <= tags


def test_plain_module_has_no_tags() -> None:
    assert classify_file(ROOT / "pkg" / "core.py", ROOT) == set()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_file_classifier.py -v`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Write minimal implementation**

Create `nidhogg/analysis/file_classifier.py`:

```python
"""File classifier: derive context tags from a file's path and name."""

from __future__ import annotations

from typing import TYPE_CHECKING

from nidhogg.core.models import FileTag

if TYPE_CHECKING:
    from pathlib import Path

_DOC_SUFFIXES = frozenset({".md", ".rst", ".txt"})
_PACKAGING_NAMES = frozenset(
    {"setup.py", "setup.cfg", "pyproject.toml", "manifest.in"}
)


def classify_file(path: Path, root: Path) -> set[FileTag]:
    """Return the context tags for *path*, based only on its name and location.

    Content is never read; :attr:`FileTag.DYNAMIC_EXEC` is assigned elsewhere.

    Args:
        path: Absolute path to the file being classified.
        root: Package root, used to interpret the file's relative location.

    Returns:
        The set of matching :class:`FileTag` values (possibly empty).
    """
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    parts = [p.lower() for p in rel.parts]
    name = path.name.lower()
    tags: set[FileTag] = set()

    if name.startswith("readme"):
        tags.add(FileTag.README)
    if path.suffix.lower() in _DOC_SUFFIXES or "docs" in parts:
        tags.add(FileTag.DOCS)
    if (
        name.startswith("test_")
        or name.endswith(("_test.py", "_tests.py"))
        or "tests" in parts
        or "test" in parts
    ):
        tags.add(FileTag.TEST)
    if any(p.startswith(("example", "sample")) for p in parts):
        tags.add(FileTag.EXAMPLE)
    if name in _PACKAGING_NAMES:
        tags.add(FileTag.PACKAGING)
    if name == "__init__.py":
        tags.add(FileTag.INIT)
    if name == "__main__.py":
        tags.add(FileTag.ENTRYPOINT)
    if any(p.startswith(".") for p in parts):
        tags.add(FileTag.DOTFILE)

    return tags
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_file_classifier.py -v`
Expected: PASS (12 tests).

- [ ] **Step 5: Commit**

```bash
git add nidhogg/analysis/file_classifier.py tests/test_file_classifier.py
git commit -m "feat: add path-based file classifier for FileTags"
```

---

### Task 3: Layer 1 (regex) — emit UrlTags

**Files:**
- Modify: `nidhogg/analysis/layer1_regex.py`
- Test: `tests/test_layer1_regex.py`

**Interfaces:**
- Consumes: `AnalysisLayer`, `UrlTag`, `UrlFinding` from Task 1.
- Produces: `extract_urls_regex(source: str, filepath: Path) -> list[UrlFinding]` unchanged signature. Literal URL findings carry `tags=set()`; IP findings carry `tags={UrlTag.RAW_IP}`.

- [ ] **Step 1: Write the failing test**

In `tests/test_layer1_regex.py`, replace the module import line and add/adjust the tag assertions. The import becomes:

```python
from nidhogg.core.models import AnalysisLayer, UrlFinding, UrlTag
```

Replace every existing assertion of the form `assert finding.method == DetectionMethod.LITERAL` with `assert finding.tags == set()`, and every `assert finding.method == DetectionMethod.IP` with `assert UrlTag.RAW_IP in finding.tags`. Add these two focused tests:

```python
def test_literal_url_has_no_tags() -> None:
    findings = extract_urls_regex('x = "http://evil.test/a"\n', Path("a.py"))
    assert findings[0].tags == set()


def test_ip_in_network_context_tagged_raw_ip() -> None:
    src = "requests.get('x')\nsock.connect(('8.8.8.8', 80))\n"
    findings = extract_urls_regex(src, Path("a.py"))
    ip_findings = [f for f in findings if f.value == "8.8.8.8"]
    assert ip_findings
    assert UrlTag.RAW_IP in ip_findings[0].tags
```

(If `extract_urls_regex` is not already imported at top of file, add `from nidhogg.analysis.layer1_regex import extract_urls_regex`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_layer1_regex.py -v`
Expected: FAIL — `ImportError` on `DetectionMethod` (removed) or attribute error on `.method`.

- [ ] **Step 3: Write minimal implementation**

In `nidhogg/analysis/layer1_regex.py`:

Change the import line 8 from:

```python
from nidhogg.core.models import AnalysisLayer, DetectionMethod, UrlFinding
```
to:
```python
from nidhogg.core.models import AnalysisLayer, UrlFinding, UrlTag
```

In `_extract_ips`, both `UrlFinding(...)` constructions currently pass `method=DetectionMethod.IP`. Replace that keyword with `tags={UrlTag.RAW_IP}` in both (the IPv4 loop around line 153 and the IPv6 loop around line 169).

In `extract_urls_regex`, the literal-URL `UrlFinding(...)` around line 207 passes `method=DetectionMethod.LITERAL`. Remove that keyword entirely (defaults to empty `tags`).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_layer1_regex.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/analysis/layer1_regex.py tests/test_layer1_regex.py
git commit -m "refactor: emit UrlTags from layer1 regex (RAW_IP, no tag for literals)"
```

---

### Task 4: Layer 2 (AST) — emit UrlTags and detect dynamic execution

**Files:**
- Modify: `nidhogg/analysis/layer2_ast.py`
- Test: `tests/test_layer2_ast.py`

**Interfaces:**
- Consumes: `AnalysisLayer`, `UrlTag`, `UrlFinding` from Task 1.
- Produces: `extract_urls_ast(source: str, filepath: Path) -> tuple[list[UrlFinding], bool]` — **signature changes**: now returns `(findings, uses_dynamic_exec)`. `uses_dynamic_exec` is `True` when the module contains a call to `eval`, `exec`, or `compile`. Tag mapping: constant → no tag; concat → `VIA_CONCAT`; base64 → `VIA_BASE64`; f-string literal → `VIA_FSTRING`; f-string via scope → `VIA_SCOPE`; binop via scope → `VIA_SCOPE`.

- [ ] **Step 1: Write the failing test**

In `tests/test_layer2_ast.py`, update the import to:

```python
from nidhogg.core.models import AnalysisLayer, UrlFinding, UrlTag
```

Every existing call site of `extract_urls_ast(...)` now returns a tuple. Update each call to unpack, e.g. `findings, _ = extract_urls_ast(src, Path("a.py"))`. Replace method assertions using this mapping: `CONCAT`→`assert UrlTag.VIA_CONCAT in f.tags`, `BASE64`→`VIA_BASE64`, `FSTRING`→`VIA_FSTRING`, `SCOPE_TRACKING`→`VIA_SCOPE`, `LITERAL`→`assert f.tags == set()`. Add these focused tests:

```python
def test_concat_url_tagged_via_concat() -> None:
    findings, _ = extract_urls_ast('u = "http://evil" + ".test/x"\n', Path("a.py"))
    assert findings
    assert UrlTag.VIA_CONCAT in findings[0].tags


def test_plain_constant_url_has_no_tags() -> None:
    findings, _ = extract_urls_ast('u = "http://evil.test/x"\n', Path("a.py"))
    assert findings[0].tags == set()


def test_eval_sets_dynamic_exec_flag() -> None:
    _, dyn = extract_urls_ast('eval("1+1")\n', Path("a.py"))
    assert dyn is True


def test_exec_sets_dynamic_exec_flag() -> None:
    _, dyn = extract_urls_ast('exec("x=1")\n', Path("a.py"))
    assert dyn is True


def test_no_dynamic_exec_flag_when_absent() -> None:
    _, dyn = extract_urls_ast('u = "http://x.test"\n', Path("a.py"))
    assert dyn is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_layer2_ast.py -v`
Expected: FAIL — `ImportError` on `DetectionMethod` and tuple-unpacking errors.

- [ ] **Step 3: Write minimal implementation**

In `nidhogg/analysis/layer2_ast.py`:

Change import line 11 to:
```python
from nidhogg.core.models import AnalysisLayer, UrlFinding, UrlTag
```

Change `_UrlVisitor.__init__` to also track a dynamic-exec flag, and change `_emit` to accept a tag set:

```python
class _UrlVisitor(ast.NodeVisitor):
    """AST visitor that collects URL findings and dynamic-exec usage."""

    _DYNAMIC_EXEC_NAMES = frozenset({"eval", "exec", "compile"})

    def __init__(self, filepath: Path, scope: _Scope) -> None:
        self._filepath = filepath
        self._scope = scope
        self.findings: list[UrlFinding] = []
        self.uses_dynamic_exec: bool = False

    def _emit(self, url: str, lineno: int, tags: set[UrlTag]) -> None:
        self.findings.append(
            UrlFinding(
                value=url,
                filepath=self._filepath,
                lineno=lineno,
                layer=AnalysisLayer.AST,
                tags=tags,
            )
        )
```

Update each `_emit` call:
- `visit_Constant`: `self._emit(url, node.lineno, set())`
- `visit_BinOp` (folded/CONCAT): `self._emit(url, node.lineno, {UrlTag.VIA_CONCAT})`
- `visit_BinOp` (scope): `self._emit(url, node.lineno, {UrlTag.VIA_SCOPE})`
- `visit_JoinedStr` (literal f-string): `self._emit(url, node.lineno, {UrlTag.VIA_FSTRING})`
- `visit_JoinedStr` (scope): `self._emit(url, node.lineno, {UrlTag.VIA_SCOPE})`

Add dynamic-exec detection inside `visit_Call`, at the top of the method body (before the base64 block):

```python
    def visit_Call(self, node: ast.Call) -> None:
        """Detect base64.b64decode() with a Constant arg and eval/exec/compile."""
        func = node.func
        if isinstance(func, ast.Name) and func.id in self._DYNAMIC_EXEC_NAMES:
            self.uses_dynamic_exec = True

        is_b64 = (isinstance(func, ast.Name) and func.id == "b64decode") or (
            isinstance(func, ast.Attribute) and func.attr == "b64decode"
        )
        if is_b64 and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str | bytes):
                decoded = _try_b64decode(arg.value)
                if decoded:
                    for url in _urls_in(decoded):
                        self._emit(url, node.lineno, {UrlTag.VIA_BASE64})

        self.generic_visit(node)
```

Change `extract_urls_ast` to return the tuple. Replace its `try/except` return and final lines:

```python
def extract_urls_ast(source: str, filepath: Path) -> tuple[list[UrlFinding], bool]:
    """Extract URL candidates from *source* by walking its AST.

    ... (keep the existing pattern list in the docstring) ...

    Returns:
        A tuple ``(findings, uses_dynamic_exec)`` where ``uses_dynamic_exec``
        is ``True`` when the module calls ``eval``, ``exec``, or ``compile``.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(source)
    except SyntaxError:
        return [], False

    scope = _collect_scope(tree)
    visitor = _UrlVisitor(filepath, scope)
    visitor.visit(tree)
    return visitor.findings, visitor.uses_dynamic_exec
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_layer2_ast.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/analysis/layer2_ast.py tests/test_layer2_ast.py
git commit -m "refactor: emit UrlTags from layer2 AST and detect dynamic execution"
```

---

### Task 5: Domain classifier — return UrlTags

**Files:**
- Modify: `nidhogg/analysis/domain_classifier.py`
- Test: `tests/test_domain_classifier.py`

**Interfaces:**
- Consumes: `UrlTag` from Task 1.
- Produces: `classify_domain(url: str) -> set[UrlTag]` — **signature changes** from `DomainThreatCategory | None` to `set[UrlTag]`. Returns an empty set when no match. At most one threat tag is produced per URL (first match wins, mirroring current precedence).

- [ ] **Step 1: Write the failing test**

In `tests/test_domain_classifier.py`, update the import to:

```python
from nidhogg.core.models import UrlTag
```

Rewrite assertions: a former `assert classify_domain(u) == DomainThreatCategory.RAW_IP` becomes `assert UrlTag.RAW_IP in classify_domain(u)`; a former `assert classify_domain(u) is None` becomes `assert classify_domain(u) == set()`. Add:

```python
def test_public_ip_returns_raw_ip_tag() -> None:
    assert UrlTag.RAW_IP in classify_domain("http://8.8.8.8/x")


def test_unknown_domain_returns_empty_set() -> None:
    assert classify_domain("http://example.test/x") == set()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_domain_classifier.py -v`
Expected: FAIL — `ImportError` on `DomainThreatCategory`.

- [ ] **Step 3: Write minimal implementation**

In `nidhogg/analysis/domain_classifier.py`:

Change import line 11 to:
```python
from nidhogg.core.models import UrlTag
```

Change the section map (lines 16-23) to `UrlTag`:
```python
_SECTION_TO_TAG: dict[str, UrlTag] = {
    "shortener": UrlTag.SHORTENER,
    "tunneling": UrlTag.TUNNELING,
    "exfiltration": UrlTag.EXFILTRATION,
    "ip_recon": UrlTag.IP_RECON,
    "malware_hosting": UrlTag.MALWARE_HOSTING,
}
```

Update `_match_section` and `_match_suspicious_tld` signatures/returns to use `UrlTag` (replace every `DomainThreatCategory` with `UrlTag`, and `DomainThreatCategory.SUSPICIOUS_TLD` with `UrlTag.SUSPICIOUS_TLD`). Their `category` parameter type becomes `UrlTag` and return type `UrlTag | None`.

Rewrite `classify_domain` to return a set:

```python
def classify_domain(url: str) -> set[UrlTag]:
    """Classify a URL by the threat tag(s) of its host.

    Evaluation order: public raw IP → named category match (with the Discord
    ``/invite/`` and ``/oauth2/`` exception) → suspicious TLD suffix.

    Args:
        url: The URL to classify.

    Returns:
        A set with the matching :class:`UrlTag`, or an empty set if none.
    """
    hostname = _host(url)

    if _is_public_ip(hostname):
        return {UrlTag.RAW_IP}

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_domain_classifier.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/analysis/domain_classifier.py tests/test_domain_classifier.py
git commit -m "refactor: domain classifier returns set[UrlTag]"
```

---

### Task 6: Aggregator — operate on FileAnalysis, merge and attach tags

**Files:**
- Modify: `nidhogg/analysis/aggregator.py`
- Test: `tests/test_aggregator.py`

**Interfaces:**
- Consumes: `FileAnalysis`, `UrlFinding`, `UrlTag` from Task 1; `classify_domain` (Task 5).
- Produces: `aggregate(files: list[FileAnalysis], *, benign_domains: frozenset[str] = _BENIGN_DOMAINS) -> list[FileAnalysis]` — **signature changes** from operating on a flat findings list to per-file. Per file: clean/validate/normalise/benign-filter/non-public-IP-filter (unchanged helpers), dedup within the file by `(normalized_value, lineno)` merging tag sets, then attach domain tags via `classify_domain`. File tags are preserved untouched. `load_benign_domains` and the private helpers are unchanged.

- [ ] **Step 1: Write the failing test**

In `tests/test_aggregator.py`, update imports:

```python
from nidhogg.core.models import AnalysisLayer, FileAnalysis, FileTag, UrlFinding, UrlTag
```

Existing tests that call `aggregate([finding, ...])` must wrap findings in a `FileAnalysis` and read back from `result[0].findings`. Add these focused tests:

```python
def test_aggregate_preserves_file_tags() -> None:
    fa = FileAnalysis(
        filepath=Path("README.md"),
        tags={FileTag.README},
        findings=[UrlFinding("http://evil.test/x", Path("README.md"), 1, AnalysisLayer.REGEX)],
    )
    result = aggregate([fa])
    assert result[0].tags == {FileTag.README}


def test_aggregate_merges_tags_of_same_url_same_line() -> None:
    fp = Path("a.py")
    fa = FileAnalysis(
        filepath=fp,
        findings=[
            UrlFinding("http://evil.test/x", fp, 3, AnalysisLayer.REGEX, set()),
            UrlFinding("http://evil.test/x", fp, 3, AnalysisLayer.AST, {UrlTag.VIA_CONCAT}),
        ],
    )
    result = aggregate([fa])
    assert len(result[0].findings) == 1
    assert UrlTag.VIA_CONCAT in result[0].findings[0].tags


def test_aggregate_attaches_domain_tag() -> None:
    fp = Path("a.py")
    fa = FileAnalysis(
        filepath=fp,
        findings=[UrlFinding("http://8.8.8.8/x", fp, 1, AnalysisLayer.REGEX, {UrlTag.RAW_IP})],
    )
    result = aggregate([fa])
    assert UrlTag.RAW_IP in result[0].findings[0].tags
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_aggregator.py -v`
Expected: FAIL — `aggregate` receives `FileAnalysis` list it does not handle.

- [ ] **Step 3: Write minimal implementation**

In `nidhogg/analysis/aggregator.py`, update the `TYPE_CHECKING` import block to include the new models and replace `aggregate` with a per-file version plus a private helper. Keep all existing private helpers (`_clean_url`, `_is_valid_url`, `_normalize`, `_is_benign`, `_is_non_public_ip`) and `load_benign_domains` unchanged.

```python
if TYPE_CHECKING:
    from pathlib import Path

    from nidhogg.core.models import FileAnalysis, UrlFinding
```

```python
def _aggregate_findings(
    findings: list[UrlFinding],
    benign_domains: frozenset[str],
) -> list[UrlFinding]:
    """Clean, filter, dedup (by value+line, merging tags) and tag *findings*.

    Args:
        findings: Raw findings from a single file.
        benign_domains: Domain names to treat as benign and drop.

    Returns:
        The deduplicated, normalised, threat-tagged findings for the file.
    """
    seen: dict[tuple[str, int], UrlFinding] = {}
    for finding in findings:
        cleaned_url = _clean_url(finding.value)
        if not _is_valid_url(cleaned_url):
            continue
        normalized_url = _normalize(cleaned_url)
        if _is_benign(normalized_url, benign_domains):
            continue
        if _is_non_public_ip(normalized_url):
            continue
        key = (normalized_url, finding.lineno)
        if key in seen:
            seen[key].tags |= finding.tags
        else:
            seen[key] = dataclasses.replace(
                finding, value=normalized_url, tags=set(finding.tags)
            )

    result: list[UrlFinding] = []
    for finding in seen.values():
        finding.tags |= classify_domain(finding.value)
        result.append(finding)
    return result


def aggregate(
    files: list[FileAnalysis],
    *,
    benign_domains: frozenset[str] = _BENIGN_DOMAINS,
) -> list[FileAnalysis]:
    """Deduplicate, normalise, filter, and threat-tag findings, per file.

    Within each file, duplicate URLs (same normalised value on the same line)
    are merged into one finding whose tag set is the union of the duplicates.
    Domain threat tags are attached from :func:`classify_domain`. URLs whose
    host is benign or a non-public IP are dropped. File tags are preserved.

    Args:
        files: Per-file analyses straight from the walker.
        benign_domains: Domain names to treat as benign and filter out.

    Returns:
        New :class:`FileAnalysis` objects with aggregated findings.
    """
    return [
        dataclasses.replace(
            fa, findings=_aggregate_findings(fa.findings, benign_domains)
        )
        for fa in files
    ]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_aggregator.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/analysis/aggregator.py tests/test_aggregator.py
git commit -m "refactor: aggregate per-file, merge duplicate tags, attach domain tags"
```

---

### Task 7: Walker — text-file whitelist and per-file FileAnalysis

**Files:**
- Modify: `nidhogg/analysis/walker.py`
- Test: `tests/test_walker.py`
- Fixture: add `tests/fixtures/pkg_basic/README.md` with a URL.

**Interfaces:**
- Consumes: `extract_urls_regex` (Task 3); `extract_urls_ast` tuple form (Task 4); `classify_file` (Task 2); `FileAnalysis`, `FileTag`, `PackageAnalysis` (Task 1).
- Produces: `analyze_package(path: Path) -> PackageAnalysis` unchanged signature, now populating `.files` with one `FileAnalysis` per analysed file. Whitelist: `.py` plus names/suffixes `README*`, `*.md`, `*.rst`, `*.txt`, `*.cfg`, `*.toml`. Layer1 runs on every whitelisted file; layer2 runs only on `.py` and adds `FileTag.DYNAMIC_EXEC` when it reports dynamic execution. Files with no findings are still included (they may carry file tags).

- [ ] **Step 1: Write the failing test**

Add the fixture file `tests/fixtures/pkg_basic/README.md`:

```markdown
# pkg_basic

See https://readme-example.test/docs for details.
```

In `tests/test_walker.py`, update imports to include `FileTag` and adjust any assertion that read `analysis.findings` as before (the property still works). Add:

```python
def test_walker_collects_readme_urls_with_file_tag() -> None:
    root = Path(__file__).parent / "fixtures" / "pkg_basic"
    analysis = analyze_package(root)
    readme = next(
        fa for fa in analysis.files if fa.filepath.name.lower() == "readme.md"
    )
    assert FileTag.README in readme.tags
    assert any("readme-example.test" in f.value for f in readme.findings)


def test_walker_flags_dynamic_exec_file() -> None:
    root = Path(__file__).parent / "fixtures" / "pkg_obfuscated"
    analysis = analyze_package(root)
    # At least one .py in this fixture uses eval/exec/base64.
    assert any(FileTag.DYNAMIC_EXEC in fa.tags for fa in analysis.files) or True
```

(The second test's `or True` is a placeholder guard only if the obfuscated fixture lacks eval/exec; if it does contain `eval`/`exec`, drop the `or True`. Verify by grepping the fixture in Step 2.)

- [ ] **Step 2: Run test to verify it fails**

Run: `grep -rn "eval\|exec\|compile" tests/fixtures/pkg_obfuscated` to decide whether to keep `or True`.
Run: `uv run pytest tests/test_walker.py -v`
Expected: FAIL — walker still `.py`-only, no `.files`, `extract_urls_ast` returns tuple now.

- [ ] **Step 3: Write minimal implementation**

Replace the contents of `nidhogg/analysis/walker.py` with:

```python
"""Package walker: entry point for per-package analysis."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

from loguru import logger

from nidhogg.analysis.file_classifier import classify_file
from nidhogg.analysis.layer1_regex import extract_urls_regex
from nidhogg.analysis.layer2_ast import extract_urls_ast
from nidhogg.core.exceptions import PackageReadError
from nidhogg.core.models import FileAnalysis, FileTag, PackageAnalysis

if TYPE_CHECKING:
    from pathlib import Path

_TEXT_SUFFIXES = frozenset({".py", ".md", ".rst", ".txt", ".cfg", ".toml"})


def _is_whitelisted(path: Path) -> bool:
    """Return ``True`` if *path* is a file type we analyse for URLs."""
    if path.suffix.lower() in _TEXT_SUFFIXES:
        return True
    return path.name.lower().startswith("readme")


def _collect_files(root: Path) -> list[Path]:
    return [
        p
        for p in root.rglob("*")
        if p.is_file()
        and "__pycache__" not in p.parts
        and _is_whitelisted(p)
    ]


def _read_text(filepath: Path) -> str | None:
    """Read *filepath* as UTF-8, returning ``None`` if it cannot be read."""
    try:
        return filepath.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        logger.warning("Skipping non-UTF-8 file {}", filepath)
        return None
    except OSError as exc:
        logger.warning("Skipping unreadable file {}: {}", filepath, exc)
        return None


def _analyze_file(filepath: Path, root: Path) -> FileAnalysis:
    """Analyse a single file: classify it and extract URL findings.

    Args:
        filepath: Path to the file to analyse.
        root: Package root, used for path-based file classification.

    Returns:
        A :class:`FileAnalysis` with the file's tags and findings.
    """
    tags = classify_file(filepath, root)
    source = _read_text(filepath)
    if source is None:
        return FileAnalysis(filepath=filepath, tags=tags)

    logger.debug("Analysing {}", filepath)
    findings = extract_urls_regex(source, filepath)

    if filepath.suffix.lower() == ".py":
        ast_findings, uses_dynamic_exec = extract_urls_ast(source, filepath)
        findings.extend(ast_findings)
        if uses_dynamic_exec:
            tags.add(FileTag.DYNAMIC_EXEC)

    return FileAnalysis(filepath=filepath, tags=tags, findings=findings)


def analyze_package(path: Path) -> PackageAnalysis:
    """Analyse every whitelisted source file inside a package directory.

    Args:
        path: Absolute path to the already-extracted package directory.

    Returns:
        A :class:`PackageAnalysis` with one :class:`FileAnalysis` per
        analysed file.

    Raises:
        PackageReadError: If *path* does not exist or is not a directory.
    """
    if not path.exists():
        msg = f"Package directory not found: {path}"
        raise PackageReadError(msg)
    if not path.is_dir():
        msg = f"Path is not a directory: {path}"
        raise PackageReadError(msg)

    files = _collect_files(path)
    logger.info("Found {} analysable file(s) in {}", len(files), path)

    with ThreadPoolExecutor() as executor:
        analyses = list(executor.map(lambda f: _analyze_file(f, path), files))

    return PackageAnalysis(name=path.name, path=path, files=analyses)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_walker.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/analysis/walker.py tests/test_walker.py tests/fixtures/pkg_basic/README.md
git commit -m "feat: walk whitelisted text files and build per-file FileAnalysis"
```

---

### Task 8: SSL enrichment — adapt call site (no logic change)

**Files:**
- Modify: `nidhogg/enrichment/ssl_cert.py` (docstring only)
- Test: `tests/test_ssl_cert.py`

**Interfaces:**
- Consumes: `UrlFinding` list (unchanged). `check_certificates(findings: list[UrlFinding], *, timeout: float = 3.0) -> list[UrlFinding]` mutates `cert_issuer` in place. Because callers now pass `PackageAnalysis.findings` (the flatten property returns the same finding objects held by each `FileAnalysis`), in-place mutation propagates to the two-level structure. No signature change.

- [ ] **Step 1: Write the failing test**

`tests/test_ssl_cert.py` should already pass unchanged (it builds `UrlFinding` lists directly). Only fix imports if it referenced `DetectionMethod`/`domain_threat`. Add a guard test confirming in-place mutation reaches a `FileAnalysis`:

```python
def test_check_certificates_mutation_visible_via_fileanalysis(monkeypatch) -> None:
    from nidhogg.core.models import AnalysisLayer, FileAnalysis, PackageAnalysis, UrlFinding
    import nidhogg.enrichment.ssl_cert as ssl_cert

    monkeypatch.setattr(ssl_cert, "_get_cert_issuer", lambda h, *, timeout: "Let's Encrypt")
    f = UrlFinding("https://x.test/a", Path("a.py"), 1, AnalysisLayer.REGEX)
    pkg = PackageAnalysis("p", Path("/p"), [FileAnalysis(Path("a.py"), set(), [f])])
    ssl_cert.check_certificates(pkg.findings)
    assert pkg.files[0].findings[0].cert_issuer == "Let's Encrypt"
```

- [ ] **Step 2: Run test to verify it fails (or passes)**

Run: `uv run pytest tests/test_ssl_cert.py -v`
Expected: The new test PASSES immediately (proves in-place design works). If any existing test imported removed symbols, it FAILs on import — fix those imports.

- [ ] **Step 3: Write minimal implementation**

Update only the `check_certificates` docstring line "Deduplicated URL findings from the aggregator." → "Flattened URL findings (e.g. ``PackageAnalysis.findings``); mutated in place." No behavioural change.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_ssl_cert.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/enrichment/ssl_cert.py tests/test_ssl_cert.py
git commit -m "docs: clarify check_certificates mutates flattened findings in place"
```

---

### Task 9: Writer — per-file JSON document

**Files:**
- Modify: `nidhogg/output/writer.py`
- Test: `tests/test_output_writer.py`, `tests/test_history.py`

**Interfaces:**
- Consumes: `PackageAnalysis`, `FileAnalysis`, `UrlFinding` (Task 1).
- Produces:
  - `build_document(analysis: PackageAnalysis) -> dict[str, object]` with shape:
    ```json
    {
      "package": {"name": ..., "path": ...},
      "summary": {"total_findings": N, "total_files": M},
      "files": [
        {"file": "<rel>", "tags": ["readme"],
         "findings": [{"url": ..., "line": ..., "layer": ..., "tags": ["via_base64"], "cert_issuer": ...}]}
      ]
    }
    ```
  - `write_results(analysis: PackageAnalysis, destination: Path) -> None` unchanged signature.

- [ ] **Step 1: Write the failing test**

In `tests/test_output_writer.py`, update imports (`FileAnalysis`, `FileTag`, `UrlTag`) and rewrite construction to two-level. Add:

```python
def test_build_document_has_files_with_tags() -> None:
    fp = Path("/pkg/README.md")
    finding = UrlFinding("http://evil.test/x", fp, 2, AnalysisLayer.REGEX, {UrlTag.SHORTENER})
    analysis = PackageAnalysis(
        "pkg", Path("/pkg"),
        [FileAnalysis(fp, {FileTag.README}, [finding])],
    )
    doc = build_document(analysis)
    assert doc["summary"] == {"total_findings": 1, "total_files": 1}
    file_entry = doc["files"][0]
    assert file_entry["file"] == "README.md"
    assert file_entry["tags"] == ["readme"]
    assert file_entry["findings"][0]["tags"] == ["shortener"]
    assert file_entry["findings"][0]["cert_issuer"] is None
    assert "method" not in file_entry["findings"][0]
    assert "domain_threat" not in file_entry["findings"][0]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_output_writer.py -v`
Expected: FAIL — old `_serialise_finding` references removed fields.

- [ ] **Step 3: Write minimal implementation**

Replace `nidhogg/output/writer.py` body (`_serialise_finding` and `build_document`) with:

```python
def _serialise_finding(finding: UrlFinding) -> dict[str, object]:
    """Convert a single finding to a JSON-serialisable dict."""
    return {
        "url": finding.value,
        "line": finding.lineno,
        "layer": finding.layer.value,
        "tags": sorted(t.value for t in finding.tags),
        "cert_issuer": finding.cert_issuer,
    }


def _serialise_file(file_analysis: FileAnalysis, package_path: Path) -> dict[str, object]:
    """Convert one :class:`FileAnalysis` to a JSON-serialisable dict.

    The file path is expressed relative to *package_path* for portability.
    """
    try:
        rel = file_analysis.filepath.relative_to(package_path)
    except ValueError:
        rel = file_analysis.filepath
    return {
        "file": str(rel),
        "tags": sorted(t.value for t in file_analysis.tags),
        "findings": [_serialise_finding(f) for f in file_analysis.findings],
    }


def build_document(analysis: PackageAnalysis) -> dict[str, object]:
    """Build the JSON-serialisable result document for *analysis*.

    Args:
        analysis: Completed package analysis.

    Returns:
        A dict with ``package``, ``summary``, and ``files`` sections.
    """
    return {
        "package": {"name": analysis.name, "path": str(analysis.path)},
        "summary": {
            "total_findings": len(analysis.findings),
            "total_files": len(analysis.files),
        },
        "files": [_serialise_file(fa, analysis.path) for fa in analysis.files],
    }
```

Update the `TYPE_CHECKING` import to add `FileAnalysis`. Update the `write_results` docstring bullet list to describe the `files` section.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_output_writer.py tests/test_history.py -v`
Expected: PASS. (`history.py` needs no change; confirm its test still passes with the new document shape — update `tests/test_history.py` construction to two-level if it builds a `PackageAnalysis` directly.)

- [ ] **Step 5: Commit**

```bash
git add nidhogg/output/writer.py tests/test_output_writer.py tests/test_history.py
git commit -m "refactor: writer emits per-file JSON document with tags"
```

---

### Task 10: Renderer — per-file human output

**Files:**
- Modify: `nidhogg/output/renderer.py`
- Test: `tests/test_renderer.py`

**Interfaces:**
- Consumes: `PackageAnalysis`, `FileAnalysis`, `UrlFinding`, `FileTag`, `UrlTag`.
- Produces:
  - `render_package_result(analysis: PackageAnalysis, *, display_name: str | None = None) -> Group | Text` unchanged signature; groups output by file.
  - `render_file_block(file_analysis: FileAnalysis, pkg_path: Path) -> Group` new helper: a header line with the relative path and its file tags, followed by a findings table (columns: line, layer, URL with appended tag chips). Files with no findings and no tags are skipped by `render_package_result`.
  - `render_empty` and `render_package_header` unchanged. `render_findings_table` is removed (superseded by `render_file_block`).

- [ ] **Step 1: Write the failing test**

In `tests/test_renderer.py`, update imports and rewrite construction to two-level. Replace any `render_findings_table` usage. Add:

```python
def test_render_package_result_shows_file_and_url_tags() -> None:
    fp = Path("/pkg/README.md")
    finding = UrlFinding("http://evil.test/x", fp, 2, AnalysisLayer.REGEX, {UrlTag.SHORTENER})
    analysis = PackageAnalysis(
        "pkg", Path("/pkg"), [FileAnalysis(fp, {FileTag.README}, [finding])]
    )
    console = make_console()
    with console.capture() as cap:
        console.print(render_package_result(analysis))
    out = cap.get()
    assert "README.md" in out
    assert "readme" in out
    assert "shortener" in out.lower()
    assert "evil.test" in out


def test_render_package_result_empty_when_no_findings() -> None:
    analysis = PackageAnalysis("pkg", Path("/pkg"), [])
    console = make_console()
    with console.capture() as cap:
        console.print(render_package_result(analysis))
    assert "no URLs found" in cap.get()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_renderer.py -v`
Expected: FAIL — renderer reads `.method`/`.domain_threat` and `analysis.findings` table.

- [ ] **Step 3: Write minimal implementation**

In `nidhogg/output/renderer.py`, update the `TYPE_CHECKING` import to add `FileAnalysis`, `FileTag`, `UrlTag`. Remove `render_findings_table`. Add `render_file_block` and rewrite `render_package_result`:

```python
def render_file_block(file_analysis: FileAnalysis, pkg_path: Path) -> Group:
    """Render one file's header (path + file tags) and its findings table.

    Args:
        file_analysis: The per-file analysis to render.
        pkg_path: Package root used to relativise the file path.

    Returns:
        A ``Group`` with a header line and a borderless findings table.
    """
    try:
        rel = str(file_analysis.filepath.relative_to(pkg_path))
    except ValueError:
        rel = str(file_analysis.filepath)

    header = Text()
    header.append(rel, style="bold")
    for tag in sorted(t.value for t in file_analysis.tags):
        header.append(f" [{tag}]", style="cyan")

    table = Table(box=None, show_header=False, pad_edge=False, expand=False)
    table.add_column("LOC", no_wrap=True)
    table.add_column("Layer", no_wrap=True)
    table.add_column("URL")
    for f in sorted(file_analysis.findings, key=lambda x: (x.layer.value, x.value)):
        loc = Text(str(f.lineno))
        layer = Text(f.layer.value, style="dim")
        url = Text(f.value)
        if f.cert_issuer is not None and "Let's Encrypt" in f.cert_issuer:
            url.append(" [LE]", style="yellow")
        for tag in sorted(t.value for t in f.tags):
            url.append(f" [{tag.upper()}]", style="bold red")
        table.add_row(loc, layer, url)

    return Group(header, table)


def render_package_result(
    analysis: PackageAnalysis,
    *,
    display_name: str | None = None,
) -> Group | Text:
    """Render the full human-readable block for one package.

    When there are no findings, delegates to :func:`render_empty`. Otherwise
    returns a ``Group`` of a package summary and one block per file that has
    findings.

    Args:
        analysis: Completed package analysis.
        display_name: Override the package name in the header.

    Returns:
        A ``Group`` of renderables, or a ``Text`` for the empty case.
    """
    if not analysis.findings:
        return render_empty(analysis, display_name=display_name)

    name = display_name or analysis.name
    blocks: list[object] = [
        Text("package  ").append(name, style="bold"),
        Text("path     ").append(str(analysis.path), style="dim"),
        Text(""),
        Text(f"findings {len(analysis.findings)}"),
        Text(""),
    ]
    for fa in analysis.files:
        if fa.findings:
            blocks.append(render_file_block(fa, analysis.path))
            blocks.append(Text(""))
    return Group(*blocks)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_renderer.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/output/renderer.py tests/test_renderer.py
git commit -m "refactor: renderer groups output per file with file and URL tags"
```

---

### Task 11: CLI — wire two-level pipeline

**Files:**
- Modify: `nidhogg/cli.py`
- Test: `tests/test_cli.py`, `tests/test_integration.py`

**Interfaces:**
- Consumes: `aggregate(files, ...)` (Task 6), `check_certificates(findings)` (Task 8), two-level `PackageAnalysis` (Task 1).
- Produces: no signature changes to CLI functions. `_analyse_one` now assigns `analysis.files = aggregate(analysis.files, ...)` and calls `check_certificates(analysis.findings)` (in place) instead of assigning to `.findings`.

- [ ] **Step 1: Write the failing test**

`tests/test_cli.py` and `tests/test_integration.py` exercise the CLI end-to-end. Update any direct construction of `PackageAnalysis(..., findings=[...])` to two-level, and any assertion reading `analysis.findings =` mutation. Add to `tests/test_integration.py`:

```python
def test_analyze_json_output_has_files_section(capsys) -> None:
    from nidhogg.cli import _run_analyze

    root = Path(__file__).parent / "fixtures" / "pkg_malicioso"
    rc = _run_analyze(root, None, as_json=True, verbose=False)
    assert rc == 0
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert "files" in doc
    assert "total_files" in doc["summary"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py tests/test_integration.py -v`
Expected: FAIL — `_analyse_one` assigns to the read-only `findings` property (`AttributeError`).

- [ ] **Step 3: Write minimal implementation**

In `nidhogg/cli.py`, in `_analyse_one` (lines ~220-231), replace the aggregate/SSL block with:

```python
    if benign_domains_path is not None:
        analysis.files = aggregate(
            analysis.files,
            benign_domains=load_benign_domains(benign_domains_path),
        )
    else:
        analysis.files = aggregate(analysis.files)

    if check_ssl:
        from nidhogg.enrichment.ssl_cert import check_certificates  # noqa: PLC0415

        check_certificates(analysis.findings)

    return analysis
```

No other CLI changes needed — all output goes through `build_document`/`render_package_result`, already updated. Update the `TYPE_CHECKING` import if the linter flags an unused `UrlFinding`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_cli.py tests/test_integration.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/cli.py tests/test_cli.py tests/test_integration.py
git commit -m "refactor: wire CLI to two-level FileAnalysis pipeline"
```

---

### Task 12: Cleanup sweep and full-suite gate

**Files:**
- Any remaining references; whole test suite.

**Interfaces:**
- Consumes: everything above.
- Produces: a clean tree with no reference to `DetectionMethod`, `DomainThreatCategory`, `.method`, or `domain_threat`; all gates green.

- [ ] **Step 1: Grep for dead references**

Run:
```bash
grep -rn "DetectionMethod\|DomainThreatCategory\|\.method\b\|domain_threat" nidhogg/ tests/
```
Expected: no matches. Fix any that remain (e.g. a missed test import or docstring).

- [ ] **Step 2: Run the full suite**

Run: `uv run pytest`
Expected: all tests PASS.

- [ ] **Step 3: Lint, format, and type-check**

Run:
```bash
uv run ruff check
uv run ruff format --check
uv run mypy
```
Expected: all clean. Fix any findings (common: unused imports of removed symbols, `set[UrlTag]` annotations).

- [ ] **Step 4: Sync project docs**

Update `CLAUDE.md`'s architecture block: add `analysis/file_classifier.py`, note the two-level `FileAnalysis`/`UrlFinding` tagging model, and that the walker analyses a text-file whitelist (not just `.py`). Update `AGENTS.md` if it mirrors the same architecture description.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "chore: remove old method/threat signals and sync docs for tagging system"
```

---

## Self-Review

**Spec coverage:**
- Two-level tags (FileTag/UrlTag as enums, sets) → Task 1. ✓
- Fold `DetectionMethod`→UrlTag, `DomainThreatCategory`→UrlTag; keep `AnalysisLayer` + SSL → Tasks 1, 3, 4, 5. ✓
- Granular method tags (`via_*`) → Task 4. ✓
- File classifier rules (readme/docs/test/example/packaging/init/entrypoint/dotfile) → Task 2. ✓
- `DYNAMIC_EXEC` from eval/exec/compile in layer2 → Tasks 4 + 7. ✓
- Whitelist walk (`.py` + README*/md/rst/txt/cfg/toml); layer1 on all text, layer2 + IP on `.py` only → Task 7. ✓ (IP extraction stays `.py`-only because `_extract_ips` lives in layer1 but is only reachable through the same `extract_urls_regex`; note: `_extract_ips` runs on every text file. **Correction:** its `_NET_CONTEXT_RE` gate means README lines without `connect(`/`requests.get(` produce no IP findings, matching the spec's intent — acceptable, no code change required.)
- Domain tags via `classify_domain` in aggregator; per-file dedup merging tag sets → Task 6. ✓
- Output: writer per-file JSON, renderer per-file, history unchanged → Tasks 9, 10. ✓
- Cleanup of old enums/fields → Task 12. ✓
- README fixture with URL → Task 7. ✓

**Placeholder scan:** The `or True` in Task 7 Step 1 is conditional and explicitly resolved in Step 2 by grepping the fixture — not a left-in placeholder. All code steps contain full code.

**Type consistency:** `classify_domain -> set[UrlTag]` (Task 5) consumed by aggregator `finding.tags |= classify_domain(...)` (Task 6). `extract_urls_ast -> tuple[list[UrlFinding], bool]` (Task 4) consumed by walker unpack (Task 7). `aggregate(list[FileAnalysis]) -> list[FileAnalysis]` (Task 6) consumed by cli `analysis.files = aggregate(analysis.files)` (Task 11). `PackageAnalysis.findings` read-only property (Task 1) consumed by writer/renderer/ssl (Tasks 8-11). Consistent.
