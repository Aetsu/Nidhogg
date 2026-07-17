# PyPI Fetch and Monitor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Nidhogg its own isolated PyPI fetcher and two new CLI capabilities: `fetch` (download and analyse one named package) and `monitor` (continuously watch the PyPI changelog, download every newly published package, and analyse it).

**Architecture:** A new `nidhogg/fetching/` package holds three independent, stdlib-only modules: `pypi_fetch.py` (download + safe archive extraction), `changelog.py` (PyPI XML-RPC changelog client), and `monitor_state.py` (persisted last-processed serial). `cli.py` is restructured from a single flat command into three subcommands (`analyze`, `fetch`, `monitor`); `_analyse_one` gains `run_url_analysis`/`run_typosquat` flags so `fetch`/`monitor` can select which checks to run without a package folder existing beforehand.

**Tech Stack:** Python 3.14 stdlib only (`urllib.request`, `tarfile`, `zipfile`, `tempfile`, `shutil`, `xmlrpc.client`, `concurrent.futures`), pytest, `unittest.mock`.

## Global Constraints

- No new dependencies.
- Mypy strict: every function has full type hints including return types.
- Docstrings: Google style, on every public function.
- Run `uv run pytest`, `uv run ruff check`, `uv run ruff format --check`, and `uv run mypy` before each commit that finishes a task.
- This plan depends on `docs/superpowers/plans/2026-07-08-typosquat-metadata-signals.md` and `docs/superpowers/plans/2026-07-09-output-persistence.md` being implemented first (`--no-typosquat-intel`, `--history-dir`, `enrich_typosquat` must already exist).
- The CLI restructure to subcommands is a deliberate breaking change: `nidhogg <path>` becomes `nidhogg analyze <path>`. No backward-compatibility shim.
- Archive extraction must reject path traversal (zip-slip / tar-slip) — this is a security-critical requirement, not a nice-to-have.

---

### Task 1: `fetching/pypi_fetch.py` — download + safe extraction

**Files:**
- Create: `nidhogg/fetching/__init__.py` (empty)
- Create: `nidhogg/fetching/pypi_fetch.py`
- Test: `tests/test_pypi_fetch.py`

**Interfaces:**
- Produces: `DownloadInfo` (frozen dataclass), `resolve_download_info(name: str, version: str | None = None, *, timeout: float = 10.0) -> DownloadInfo`, `download_and_extract(name: str, version: str | None = None) -> Path`, `fetched_package(name: str, version: str | None = None, *, keep: bool = False, keep_dir: Path | None = None) -> AbstractContextManager[Path]`.
- Raises: `nidhogg.core.exceptions.PackageReadError` on any resolution/download/extraction failure (network error, package not found, no sdist/wheel available, unsafe archive path).

- [ ] **Step 1: Write the failing tests**

Create `nidhogg/fetching/__init__.py` (empty file).

Create `tests/test_pypi_fetch.py`:

```python
"""Tests for fetching/pypi_fetch.py."""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from nidhogg.core.exceptions import PackageReadError
from nidhogg.fetching.pypi_fetch import (
    DownloadInfo,
    _safe_extract_tar,
    _safe_extract_zip,
    download_and_extract,
    fetched_package,
    resolve_download_info,
)

_PYPI_URLS_PAYLOAD = {
    "urls": [
        {
            "packagetype": "bdist_wheel",
            "url": "https://files.pypi.org/packages/pkg-1.0-py3-none-any.whl",
            "filename": "pkg-1.0-py3-none-any.whl",
        },
        {
            "packagetype": "sdist",
            "url": "https://files.pypi.org/packages/pkg-1.0.tar.gz",
            "filename": "pkg-1.0.tar.gz",
        },
    ]
}


def _make_tar_gz(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _make_zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_resolve_download_info_prefers_sdist():
    with patch(
        "nidhogg.fetching.pypi_fetch._fetch_pypi_urls_json",
        return_value=_PYPI_URLS_PAYLOAD,
    ):
        info = resolve_download_info("pkg")
    assert info.packagetype == "sdist"
    assert info.filename == "pkg-1.0.tar.gz"


def test_resolve_download_info_falls_back_to_wheel():
    payload = {"urls": [_PYPI_URLS_PAYLOAD["urls"][0]]}
    with patch(
        "nidhogg.fetching.pypi_fetch._fetch_pypi_urls_json", return_value=payload
    ):
        info = resolve_download_info("pkg")
    assert info.packagetype == "bdist_wheel"


def test_resolve_download_info_raises_when_no_files():
    with patch(
        "nidhogg.fetching.pypi_fetch._fetch_pypi_urls_json", return_value={"urls": []}
    ):
        with pytest.raises(PackageReadError):
            resolve_download_info("pkg")


def test_resolve_download_info_raises_on_network_error():
    import urllib.error

    with patch(
        "nidhogg.fetching.pypi_fetch._fetch_pypi_urls_json",
        side_effect=urllib.error.URLError("boom"),
    ):
        with pytest.raises(PackageReadError):
            resolve_download_info("nonexistent-pkg")


def test_safe_extract_tar_extracts_normal_archive(tmp_path: Path):
    archive = tmp_path / "pkg.tar.gz"
    archive.write_bytes(_make_tar_gz({"pkg/setup.py": b"print('hi')"}))
    dest = tmp_path / "extracted"
    dest.mkdir()
    _safe_extract_tar(archive, dest)
    assert (dest / "pkg" / "setup.py").read_bytes() == b"print('hi')"


def test_safe_extract_tar_rejects_path_traversal(tmp_path: Path):
    archive = tmp_path / "evil.tar.gz"
    archive.write_bytes(_make_tar_gz({"../evil.txt": b"pwned"}))
    dest = tmp_path / "extracted"
    dest.mkdir()
    with pytest.raises(PackageReadError):
        _safe_extract_tar(archive, dest)
    assert not (tmp_path / "evil.txt").exists()


def test_safe_extract_zip_extracts_normal_archive(tmp_path: Path):
    archive = tmp_path / "pkg.zip"
    archive.write_bytes(_make_zip({"pkg/setup.py": b"print('hi')"}))
    dest = tmp_path / "extracted"
    dest.mkdir()
    _safe_extract_zip(archive, dest)
    assert (dest / "pkg" / "setup.py").read_bytes() == b"print('hi')"


def test_safe_extract_zip_rejects_path_traversal(tmp_path: Path):
    archive = tmp_path / "evil.zip"
    archive.write_bytes(_make_zip({"../evil.txt": b"pwned"}))
    dest = tmp_path / "extracted"
    dest.mkdir()
    with pytest.raises(PackageReadError):
        _safe_extract_zip(archive, dest)
    assert not (tmp_path / "evil.txt").exists()


def test_safe_extract_zip_rejects_absolute_path(tmp_path: Path):
    archive = tmp_path / "evil2.zip"
    archive.write_bytes(_make_zip({"/etc/evil.txt": b"pwned"}))
    dest = tmp_path / "extracted"
    dest.mkdir()
    with pytest.raises(PackageReadError):
        _safe_extract_zip(archive, dest)


def test_download_and_extract_downloads_and_extracts(tmp_path: Path):
    tar_bytes = _make_tar_gz({"pkg-1.0/setup.py": b"print('hi')"})

    def _fake_urlretrieve(url: str, filename: str) -> tuple[str, object]:  # noqa: ARG001
        Path(filename).write_bytes(tar_bytes)
        return filename, None

    with (
        patch(
            "nidhogg.fetching.pypi_fetch.resolve_download_info",
            return_value=DownloadInfo(
                url="https://example.com/pkg-1.0.tar.gz",
                filename="pkg-1.0.tar.gz",
                packagetype="sdist",
            ),
        ),
        patch(
            "nidhogg.fetching.pypi_fetch.urllib.request.urlretrieve",
            side_effect=_fake_urlretrieve,
        ),
    ):
        result = download_and_extract("pkg")

    assert (result / "pkg-1.0" / "setup.py").exists()


def test_fetched_package_cleans_up_by_default(tmp_path: Path):
    tar_bytes = _make_tar_gz({"pkg-1.0/setup.py": b"x"})

    def _fake_urlretrieve(url: str, filename: str) -> tuple[str, object]:  # noqa: ARG001
        Path(filename).write_bytes(tar_bytes)
        return filename, None

    with (
        patch(
            "nidhogg.fetching.pypi_fetch.resolve_download_info",
            return_value=DownloadInfo(
                url="https://example.com/pkg-1.0.tar.gz",
                filename="pkg-1.0.tar.gz",
                packagetype="sdist",
            ),
        ),
        patch(
            "nidhogg.fetching.pypi_fetch.urllib.request.urlretrieve",
            side_effect=_fake_urlretrieve,
        ),
    ):
        with fetched_package("pkg") as path:
            assert path.exists()
        assert not path.exists()


def test_fetched_package_keeps_when_requested(tmp_path: Path):
    tar_bytes = _make_tar_gz({"pkg-1.0/setup.py": b"x"})

    def _fake_urlretrieve(url: str, filename: str) -> tuple[str, object]:  # noqa: ARG001
        Path(filename).write_bytes(tar_bytes)
        return filename, None

    with (
        patch(
            "nidhogg.fetching.pypi_fetch.resolve_download_info",
            return_value=DownloadInfo(
                url="https://example.com/pkg-1.0.tar.gz",
                filename="pkg-1.0.tar.gz",
                packagetype="sdist",
            ),
        ),
        patch(
            "nidhogg.fetching.pypi_fetch.urllib.request.urlretrieve",
            side_effect=_fake_urlretrieve,
        ),
    ):
        with fetched_package("pkg", keep=True) as path:
            kept_path = path
        assert kept_path.exists()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_pypi_fetch.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'nidhogg.fetching'`.

- [ ] **Step 3: Implement**

Create `nidhogg/fetching/pypi_fetch.py`:

```python
"""Self-contained PyPI package fetcher for on-demand and monitored scans.

Downloads a single named package (or its latest release) from PyPI and
extracts it to a temporary directory for analysis. Independent from and
unrelated to any external bulk downloader — used only by the ``fetch`` and
``monitor`` CLI commands.
"""

from __future__ import annotations

import json
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from loguru import logger

from nidhogg.core.exceptions import PackageReadError

_REQUEST_TIMEOUT = 10.0


@dataclass(frozen=True)
class DownloadInfo:
    """Resolved download location for a package release.

    Attributes:
        url: Direct download URL for the archive.
        filename: Archive filename, used to pick the extraction strategy.
        packagetype: PyPI's package type label (``"sdist"`` or ``"bdist_wheel"``).
    """

    url: str
    filename: str
    packagetype: str


def _fetch_pypi_urls_json(name: str, version: str | None) -> dict[str, Any]:
    """Fetch the raw PyPI JSON API payload listing download URLs.

    Args:
        name: Package name.
        version: Specific version, or ``None`` for the latest release.

    Returns:
        The parsed JSON document.

    Raises:
        urllib.error.URLError: On network failure or a non-2xx response.
        ValueError: If the response body is not valid JSON.
    """
    url = (
        f"https://pypi.org/pypi/{name}/{version}/json"
        if version
        else f"https://pypi.org/pypi/{name}/json"
    )
    with urllib.request.urlopen(url, timeout=_REQUEST_TIMEOUT) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))  # type: ignore[no-any-return]


def resolve_download_info(
    name: str, version: str | None = None, *, timeout: float = _REQUEST_TIMEOUT
) -> DownloadInfo:
    """Resolve the sdist (preferred) or wheel download URL for a package.

    Args:
        name: Package name to look up.
        version: Specific version, or ``None`` for the latest release.
        timeout: Network timeout in seconds (currently informational; the
            underlying fetch uses the module-level default).

    Returns:
        The resolved :class:`DownloadInfo`.

    Raises:
        PackageReadError: If the lookup fails, or no sdist/wheel is available.
    """
    del timeout  # reserved for future per-call override; fetch uses the module default
    try:
        payload = _fetch_pypi_urls_json(name, version)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        msg = f"Could not resolve download info for {name!r}: {exc}"
        raise PackageReadError(msg) from exc

    urls: list[dict[str, Any]] = payload.get("urls", [])
    sdist = next((u for u in urls if u.get("packagetype") == "sdist"), None)
    chosen = sdist or next(
        (u for u in urls if u.get("packagetype") == "bdist_wheel"), None
    )
    if chosen is None:
        msg = f"No downloadable sdist or wheel found for {name!r}"
        raise PackageReadError(msg)

    return DownloadInfo(
        url=str(chosen["url"]),
        filename=str(chosen["filename"]),
        packagetype=str(chosen["packagetype"]),
    )


def _safe_extract_tar(archive_path: Path, dest: Path) -> None:
    """Extract a tar(.gz) archive, rejecting path traversal and unsafe members.

    Args:
        archive_path: Path to the ``.tar``/``.tar.gz`` archive.
        dest: Directory to extract into.

    Raises:
        PackageReadError: If a member would extract outside *dest*.
    """
    with tarfile.open(archive_path) as tf:
        try:
            tf.extractall(dest, filter="data")
        except tarfile.FilterError as exc:
            msg = f"Unsafe path in archive {archive_path.name!r}: {exc}"
            raise PackageReadError(msg) from exc


def _safe_extract_zip(archive_path: Path, dest: Path) -> None:
    """Extract a zip (or wheel) archive, rejecting path traversal.

    ``zipfile`` has no built-in equivalent to ``tarfile``'s ``filter="data"``,
    so every member path is validated against *dest* before anything is
    written.

    Args:
        archive_path: Path to the ``.zip``/``.whl`` archive.
        dest: Directory to extract into.

    Raises:
        PackageReadError: If a member would extract outside *dest*.
    """
    resolved_dest = dest.resolve()
    with zipfile.ZipFile(archive_path) as zf:
        for member in zf.infolist():
            target = (dest / member.filename).resolve()
            if not target.is_relative_to(resolved_dest):
                msg = f"Unsafe path in archive {archive_path.name!r}: {member.filename!r}"
                raise PackageReadError(msg)
        zf.extractall(dest)


def download_and_extract(name: str, version: str | None = None) -> Path:
    """Download *name* from PyPI and extract it to a fresh temporary directory.

    Args:
        name: Package name to download.
        version: Specific version, or ``None`` for the latest release.

    Returns:
        Path to the directory containing the extracted contents. The caller
        is responsible for cleaning it up (see :func:`fetched_package`).

    Raises:
        PackageReadError: If resolution, download, or extraction fails.
    """
    info = resolve_download_info(name, version)
    tmp_dir = Path(tempfile.mkdtemp(prefix="nidhogg-fetch-"))
    archive_path = tmp_dir / info.filename

    try:
        urllib.request.urlretrieve(info.url, archive_path)  # noqa: S310
    except (urllib.error.URLError, TimeoutError) as exc:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        msg = f"Could not download {info.url!r}: {exc}"
        raise PackageReadError(msg) from exc

    extract_dir = tmp_dir / "extracted"
    extract_dir.mkdir()
    try:
        if info.filename.endswith((".tar.gz", ".tgz")):
            _safe_extract_tar(archive_path, extract_dir)
        elif info.filename.endswith((".zip", ".whl")):
            _safe_extract_zip(archive_path, extract_dir)
        else:
            msg = f"Unsupported archive format: {info.filename!r}"
            raise PackageReadError(msg)
    except PackageReadError:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise

    return extract_dir


@contextmanager
def fetched_package(
    name: str,
    version: str | None = None,
    *,
    keep: bool = False,
    keep_dir: Path | None = None,
) -> Iterator[Path]:
    """Download, extract, yield, and (by default) clean up a package.

    Args:
        name: Package name to download.
        version: Specific version, or ``None`` for the latest release.
        keep: When ``False`` (default), delete the downloaded archive and
            extracted directory on exit. When ``True``, keep them.
        keep_dir: When *keep* is ``True`` and this is provided, move the
            extracted directory here instead of leaving it under the
            system temp directory.

    Yields:
        Path to the extracted package directory.
    """
    extract_dir = download_and_extract(name, version)
    try:
        yield extract_dir
    finally:
        if not keep:
            shutil.rmtree(extract_dir.parent, ignore_errors=True)
        elif keep_dir is not None:
            keep_dir.mkdir(parents=True, exist_ok=True)
            final = keep_dir / extract_dir.name
            shutil.move(str(extract_dir), str(final))
            logger.info("Kept downloaded package at {}", final)
        else:
            logger.info("Kept downloaded package at {}", extract_dir)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_pypi_fetch.py -v`
Expected: PASS, all 12 tests.

Run: `uv run ruff check nidhogg/fetching/ && uv run mypy nidhogg/fetching/`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/fetching/__init__.py nidhogg/fetching/pypi_fetch.py tests/test_pypi_fetch.py
git commit -m "feat(fetching): add self-contained PyPI download + safe extraction"
```

---

### Task 2: `fetching/changelog.py` — PyPI changelog client

**Files:**
- Create: `nidhogg/fetching/changelog.py`
- Test: `tests/test_changelog.py`

**Interfaces:**
- Produces: `ChangelogEntry` (frozen dataclass with `.is_new_project: bool` property), `ChangelogSource` (`Protocol`), `ChangelogClient` (implements `ChangelogSource`).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_changelog.py`:

```python
"""Tests for fetching/changelog.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from nidhogg.fetching.changelog import ChangelogClient, ChangelogEntry


def test_changelog_entry_is_new_project_true_for_create():
    entry = ChangelogEntry(name="pkg", version="", timestamp=1, action="create", serial=1)
    assert entry.is_new_project is True


def test_changelog_entry_is_new_project_false_for_release():
    entry = ChangelogEntry(
        name="pkg", version="1.0", timestamp=1, action="new release", serial=1
    )
    assert entry.is_new_project is False


def test_changelog_client_current_serial():
    fake_proxy = MagicMock()
    fake_proxy.changelog_last_serial.return_value = 42
    with patch(
        "nidhogg.fetching.changelog.xmlrpc.client.ServerProxy",
        return_value=fake_proxy,
    ):
        client = ChangelogClient()
        assert client.current_serial() == 42


def test_changelog_client_entries_since_filters_by_serial():
    fake_proxy = MagicMock()
    fake_proxy.changelog_since_serial.return_value = [
        ("newpkg", "", 1000, "create", 10),
        ("oldpkg", "1.0", 1001, "new release", 11),
    ]
    with patch(
        "nidhogg.fetching.changelog.xmlrpc.client.ServerProxy",
        return_value=fake_proxy,
    ):
        client = ChangelogClient()
        entries = client.entries_since(9)
    assert len(entries) == 2
    assert entries[0].name == "newpkg"
    assert entries[0].is_new_project is True
    assert entries[1].is_new_project is False
    fake_proxy.changelog_since_serial.assert_called_once_with(9)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_changelog.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'nidhogg.fetching.changelog'`.

- [ ] **Step 3: Implement**

Create `nidhogg/fetching/changelog.py`:

```python
"""PyPI changelog client for discovering newly published packages."""

from __future__ import annotations

import xmlrpc.client
from dataclasses import dataclass
from typing import Protocol

_PYPI_XMLRPC_URL = "https://pypi.org/pypi"
_TIMEOUT = 30.0


class _TimeoutTransport(xmlrpc.client.SafeTransport):
    """``SafeTransport`` that bounds the HTTPS connection with a timeout.

    ``xmlrpc.client.ServerProxy`` has no timeout kwarg of its own, and
    ``socket.setdefaulttimeout()`` would be a global side effect. Overriding
    ``make_connection`` to pass the timeout into the ``HTTPSConnection`` it
    creates keeps it scoped to this transport instance.
    """

    def __init__(self, timeout: float) -> None:
        super().__init__()
        self._timeout = timeout

    def make_connection(self, host: str) -> xmlrpc.client.http.client.HTTPConnection:
        connection = super().make_connection(host)
        connection.timeout = self._timeout
        return connection


@dataclass(frozen=True)
class ChangelogEntry:
    """A single PyPI changelog event.

    Attributes:
        name: Package name the event applies to.
        version: Version string (empty for project-level events).
        timestamp: Unix timestamp of the event.
        action: PyPI's action label (e.g. ``"create"``, ``"new release"``).
        serial: Monotonically increasing changelog serial number.
    """

    name: str
    version: str
    timestamp: int
    action: str
    serial: int

    @property
    def is_new_project(self) -> bool:
        """Whether this event represents a brand-new project being created."""
        return self.action == "create"


class ChangelogSource(Protocol):
    """Interface for fetching PyPI changelog data (for test substitution)."""

    def current_serial(self) -> int: ...

    def entries_since(self, serial: int) -> list[ChangelogEntry]: ...


class ChangelogClient:
    """Real ``ChangelogSource`` backed by the PyPI XML-RPC API."""

    def __init__(self, url: str = _PYPI_XMLRPC_URL, timeout: float = _TIMEOUT) -> None:
        """Create a client bound to *url* with a per-connection *timeout*.

        Args:
            url: PyPI XML-RPC endpoint.
            timeout: Per-connection timeout in seconds.
        """
        transport = _TimeoutTransport(timeout)
        self._proxy = xmlrpc.client.ServerProxy(url, transport=transport)

    def current_serial(self) -> int:
        """Return the current changelog serial number."""
        return int(self._proxy.changelog_last_serial())  # type: ignore[attr-defined]

    def entries_since(self, serial: int) -> list[ChangelogEntry]:
        """Return every changelog event with serial greater than *serial*.

        Args:
            serial: The last known serial number.

        Returns:
            All changelog entries recorded after *serial*.
        """
        raw: list[tuple[str, str, int, str, int]] = (
            self._proxy.changelog_since_serial(serial)  # type: ignore[attr-defined]
        )
        return [ChangelogEntry(*entry) for entry in raw]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_changelog.py -v`
Expected: PASS, all 4 tests.

Run: `uv run ruff check nidhogg/fetching/changelog.py && uv run mypy nidhogg/fetching/changelog.py`
Expected: no errors. (If mypy complains about the `make_connection` return type against `xmlrpc.client.http.client.HTTPConnection` not resolving cleanly, replace the annotation with `object` and cast at the `connection.timeout = ...` line with `# type: ignore[attr-defined]` — either is acceptable; prefer keeping the precise type if it type-checks cleanly.)

- [ ] **Step 5: Commit**

```bash
git add nidhogg/fetching/changelog.py tests/test_changelog.py
git commit -m "feat(fetching): add PyPI changelog client"
```

---

### Task 3: `fetching/monitor_state.py` — persisted progress marker

**Files:**
- Create: `nidhogg/fetching/monitor_state.py`
- Test: `tests/test_monitor_state.py`

**Interfaces:**
- Produces: `MonitorState` (frozen dataclass with `.last_serial: int`), `load_state(index_file: Path) -> MonitorState | None`, `save_state(index_file: Path, state: MonitorState) -> None`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_monitor_state.py`:

```python
"""Tests for fetching/monitor_state.py."""

from __future__ import annotations

from pathlib import Path

from nidhogg.fetching.monitor_state import MonitorState, load_state, save_state


def test_load_state_returns_none_when_file_missing(tmp_path: Path):
    assert load_state(tmp_path / "missing.json") is None


def test_save_then_load_round_trips(tmp_path: Path):
    index_file = tmp_path / "state.json"
    save_state(index_file, MonitorState(last_serial=12345))
    loaded = load_state(index_file)
    assert loaded == MonitorState(last_serial=12345)


def test_save_state_creates_parent_directories(tmp_path: Path):
    index_file = tmp_path / "a" / "b" / "state.json"
    save_state(index_file, MonitorState(last_serial=1))
    assert index_file.exists()


def test_load_state_returns_none_on_corrupt_json(tmp_path: Path):
    index_file = tmp_path / "state.json"
    index_file.write_text("not json", encoding="utf-8")
    assert load_state(index_file) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_monitor_state.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'nidhogg.fetching.monitor_state'`.

- [ ] **Step 3: Implement**

Create `nidhogg/fetching/monitor_state.py`:

```python
"""Persisted progress marker for the PyPI changelog monitor."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class MonitorState:
    """Persisted progress marker for ``nidhogg monitor``.

    Attributes:
        last_serial: The highest PyPI changelog serial processed so far.
    """

    last_serial: int


def load_state(index_file: Path) -> MonitorState | None:
    """Load the persisted monitor state, if any.

    Args:
        index_file: Path to the state JSON file.

    Returns:
        The persisted :class:`MonitorState`, or ``None`` if the file does
        not exist or cannot be parsed.
    """
    if not index_file.exists():
        return None
    try:
        data = json.loads(index_file.read_text(encoding="utf-8"))
        return MonitorState(last_serial=int(data["last_serial"]))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def save_state(index_file: Path, state: MonitorState) -> None:
    """Persist *state* to *index_file*, creating parent directories as needed.

    Args:
        index_file: Path to the state JSON file.
        state: The state to persist.
    """
    index_file.parent.mkdir(parents=True, exist_ok=True)
    index_file.write_text(json.dumps(asdict(state)), encoding="utf-8")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_monitor_state.py -v`
Expected: PASS, all 4 tests.

Run: `uv run ruff check nidhogg/fetching/monitor_state.py && uv run mypy nidhogg/fetching/monitor_state.py`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/fetching/monitor_state.py tests/test_monitor_state.py
git commit -m "feat(fetching): add persisted monitor state (last processed serial)"
```

---

### Task 4: Restructure `cli.py` into `analyze`/`fetch`/`monitor` subcommands

**Files:**
- Modify: `nidhogg/cli.py` (full rewrite)
- Modify: `tests/test_cli.py` (fix 4 existing parser tests for the new subcommand syntax)

**Interfaces:**
- Consumes: `fetched_package` (Task 1), `ChangelogClient` (Task 2), `MonitorState`/`load_state`/`save_state` (Task 3).
- Produces: `_analyse_one(..., run_url_analysis: bool = True, run_typosquat: bool = True)`; `_run_fetch(...)`; `_run_monitor(...)`; CLI invocation becomes `nidhogg analyze|fetch|monitor ...`.

- [ ] **Step 1: Fix the 4 existing parser tests for the new subcommand syntax**

In `tests/test_cli.py`, the following four tests call `parser.parse_args([...])` with a bare path as the first element. Update each to prepend `"analyze"`:

```python
def test_build_parser_typosquat_intel_defaults_true():
    parser = _build_parser()
    args = parser.parse_args(["analyze", "some/path"])
    assert args.typosquat_intel is True


def test_build_parser_no_typosquat_intel_sets_false():
    parser = _build_parser()
    args = parser.parse_args(["analyze", "some/path", "--no-typosquat-intel"])
    assert args.typosquat_intel is False


def test_build_parser_history_dir_defaults_none():
    parser = _build_parser()
    args = parser.parse_args(["analyze", "some/path"])
    assert args.history_dir is None


def test_build_parser_history_dir_accepts_path():
    parser = _build_parser()
    args = parser.parse_args(["analyze", "some/path", "--history-dir", "/tmp/hist"])
    assert str(args.history_dir) == "/tmp/hist"
```

Run: `uv run pytest tests/test_cli.py -v`
Expected: FAIL for these 4 (still using the old flat parser) — confirms the change is needed before Step 3 rewrites `cli.py`.

- [ ] **Step 2: Run the full suite to confirm the current baseline**

Run: `uv run pytest tests/ -v`
Expected: everything else PASSes; only the 4 tests above (and, after Step 3, none — this step is just the "before" baseline).

- [ ] **Step 3: Implement — replace `nidhogg/cli.py` entirely**

Replace the full contents of `nidhogg/cli.py` with:

```python
"""Command-line interface for Nidhogg."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

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

if TYPE_CHECKING:
    pass

_EXIT_ERROR = 2

# Matches the version suffix in PyPI sdist/wheel folder names, e.g. "requests-2.31.0".
_VERSION_SUFFIX_RE = re.compile(r"^(.+?)-(\d[\w.]*)$")


def _infer_package_name(package_path: Path) -> str | None:
    """Infer the package name from metadata files or the directory name.

    Tries, in order:
    1. ``pyproject.toml`` — ``[project].name`` or ``[tool.poetry].name``.
    2. ``setup.cfg`` — ``[metadata].name``.
    3. Directory name with version suffix stripped
       (e.g. ``requests-2.31.0`` → ``requests``).

    Args:
        package_path: Root directory of the extracted package.

    Returns:
        The inferred package name, or ``None`` if it cannot be determined.
    """
    pyproject = package_path / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            name = data.get("project", {}).get("name") or data.get("tool", {}).get(
                "poetry", {}
            ).get("name")
            if name:
                return str(name)
        except Exception:  # noqa: BLE001,S110
            pass

    setup_cfg = package_path / "setup.cfg"
    if setup_cfg.exists():
        try:
            import configparser  # noqa: PLC0415

            cfg = configparser.ConfigParser()
            cfg.read_string(setup_cfg.read_text(encoding="utf-8"))
            name = cfg.get("metadata", "name", fallback=None)
            if name:
                return name
        except Exception:  # noqa: BLE001,S110
            pass

    folder = package_path.name
    match = _VERSION_SUFFIX_RE.match(folder)
    if match:
        return match.group(1)

    return folder or None


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
        "--update-top-packages",
        action="store_true",
        dest="update_top_packages",
        help=(
            "Fetch the latest top-PyPI-packages list from the canonical source "
            "and update the bundled cache before running analysis. "
            "Requires network access."
        ),
    )
    analyze.add_argument(
        "--no-typosquat-intel",
        action="store_false",
        dest="typosquat_intel",
        help=(
            "Skip live PyPI/RDAP metadata enrichment for typosquat findings "
            "(enabled by default; requires network access when a match is found)."
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
        "--no-check-urls",
        action="store_false",
        dest="check_urls",
        help="Skip URL extraction (walker/layers/aggregator/SSL check).",
    )
    fetch.add_argument(
        "--no-check-typosquat",
        action="store_false",
        dest="check_typosquat",
        help="Skip the typosquatting check.",
    )
    fetch.add_argument(
        "--no-typosquat-intel",
        action="store_false",
        dest="typosquat_intel",
        help="Skip live PyPI/RDAP metadata enrichment for typosquat findings.",
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
        "--no-check-urls",
        action="store_false",
        dest="check_urls",
        help="Skip URL extraction for every newly discovered package.",
    )
    monitor.add_argument(
        "--no-check-typosquat",
        action="store_false",
        dest="check_typosquat",
        help="Skip the typosquatting check for every newly discovered package.",
    )
    monitor.add_argument(
        "--no-typosquat-intel",
        action="store_false",
        dest="typosquat_intel",
        help="Skip live PyPI/RDAP metadata enrichment for typosquat findings.",
    )
    monitor.add_argument(
        "--keep-download",
        type=Path,
        default=None,
        metavar="DIR",
        dest="keep_download",
        help="Keep every downloaded/extracted package under DIR instead of deleting it.",
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
    package_name: str | None = None,
    typosquat_intel: bool = True,
    run_url_analysis: bool = True,
    run_typosquat: bool = True,
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
        run_url_analysis: When ``True`` (default), run the walker/layers/
            aggregator/SSL pipeline over *package_path*. When ``False``,
            *package_path* is not read and the analysis starts empty (used
            by ``fetch``/``monitor`` when only the typosquat check was
            requested).
        run_typosquat: When ``True`` (default) and *package_name* is given,
            run the typosquatting check.

    Returns:
        A ``(PackageAnalysis, Verdict)`` tuple, or ``None`` on read error.
    """
    if run_url_analysis:
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
    else:
        analysis = PackageAnalysis(
            name=package_name or package_path.name, path=package_path
        )

    if run_typosquat and package_name is not None:
        from nidhogg.analysis.typosquat import check_typosquatting  # noqa: PLC0415

        analysis.typosquat = check_typosquatting(package_name)
        if analysis.typosquat is not None and typosquat_intel:
            from nidhogg.enrichment.pypi_metadata import enrich_typosquat  # noqa: PLC0415

            analysis.typosquat = enrich_typosquat(analysis.typosquat)

    verdict = classify(analysis)

    return analysis, verdict


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
            package_name=_infer_package_name(pkg_dir),
            typosquat_intel=typosquat_intel,
        )
        if result is None:
            exit_code = _EXIT_ERROR
            continue

        analysis, verdict = result
        if verdict is not Verdict.CLEAN and exit_code != _EXIT_ERROR:
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


def _run_fetch(  # noqa: PLR0913
    name: str,
    version: str | None,
    output: Path | None,
    *,
    as_json: bool,
    verbose: bool,
    check_urls: bool,
    check_typosquat: bool,
    typosquat_intel: bool,
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
        check_urls: Run the URL-extraction pipeline over the downloaded source.
        check_typosquat: Run the typosquatting check against *name*.
        typosquat_intel: Enrich typosquat matches with live PyPI/RDAP metadata.
        keep_download: ``None`` to delete after analysis; ``""`` to keep in
            place; a non-empty string is a directory to move the extracted
            package into.
        history_dir: When provided, append the result document as JSONL
            under this directory.

    Returns:
        ``0`` for a clean package, ``1`` for suspicious/malicious, ``2`` on error.
    """
    if not verbose:
        logger.remove()

    from nidhogg.fetching.pypi_fetch import fetched_package  # noqa: PLC0415

    keep = keep_download is not None
    keep_dir = Path(keep_download) if keep_download else None

    try:
        with fetched_package(name, version, keep=keep, keep_dir=keep_dir) as path:
            result = _analyse_one(
                path,
                package_name=name,
                typosquat_intel=typosquat_intel,
                run_url_analysis=check_urls,
                run_typosquat=check_typosquat,
            )
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

    return 0 if verdict is Verdict.CLEAN else 1


def _analyse_new_package(
    name: str,
    *,
    check_urls: bool,
    check_typosquat: bool,
    typosquat_intel: bool,
    keep_download: Path | None,
) -> tuple[PackageAnalysis, Verdict] | None:
    """Download, analyse, and clean up a single monitor-discovered package.

    Args:
        name: PyPI package name to download and analyse.
        check_urls: Run the URL-extraction pipeline over the downloaded source.
        check_typosquat: Run the typosquatting check against *name*.
        typosquat_intel: Enrich typosquat matches with live PyPI/RDAP metadata.
        keep_download: When provided, keep the extracted package under a
            per-package subdirectory of this directory.

    Returns:
        A ``(PackageAnalysis, Verdict)`` tuple, or ``None`` on read error.
    """
    from nidhogg.fetching.pypi_fetch import fetched_package  # noqa: PLC0415

    keep = keep_download is not None
    keep_dir = keep_download / name if keep_download is not None else None
    with fetched_package(name, keep=keep, keep_dir=keep_dir) as path:
        return _analyse_one(
            path,
            package_name=name,
            typosquat_intel=typosquat_intel,
            run_url_analysis=check_urls,
            run_typosquat=check_typosquat,
        )


def _run_monitor(  # noqa: PLR0913
    *,
    interval: int,
    index_file: Path | None,
    concurrency: int,
    check_urls: bool,
    check_typosquat: bool,
    typosquat_intel: bool,
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
        check_urls: Run the URL-extraction pipeline for each new package.
        check_typosquat: Run the typosquatting check for each new package.
        typosquat_intel: Enrich typosquat matches with live PyPI/RDAP metadata.
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
            entries = [
                e for e in client.entries_since(last_serial) if e.is_new_project
            ]
            logger.info(
                "Monitor: {} new package(s) since serial {}", len(entries), last_serial
            )

            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                futures = {
                    pool.submit(
                        _analyse_new_package,
                        entry.name,
                        check_urls=check_urls,
                        check_typosquat=check_typosquat,
                        typosquat_intel=typosquat_intel,
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
                        from nidhogg.output.history import append_finding  # noqa: PLC0415

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


def main() -> None:
    """Entry point for the ``nidhogg`` CLI."""
    parser = _build_parser()
    args = parser.parse_args()
    _warn_if_top_packages_stale()

    if args.command == "analyze":
        package_path: Path = args.package_path
        if args.update_top_packages:
            from nidhogg.analysis.typosquat import update_top_packages  # noqa: PLC0415

            update_top_packages()

        if args.batch:
            sys.exit(
                _run_batch(
                    package_path,
                    args.output,
                    as_json=args.json,
                    verbose=args.verbose,
                    benign_domains_path=args.benign_domains,
                    check_ssl=args.check_ssl,
                    typosquat_intel=args.typosquat_intel,
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
                    package_name=_infer_package_name(package_path),
                    typosquat_intel=args.typosquat_intel,
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
                check_urls=args.check_urls,
                check_typosquat=args.check_typosquat,
                typosquat_intel=args.typosquat_intel,
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
                check_urls=args.check_urls,
                check_typosquat=args.check_typosquat,
                typosquat_intel=args.typosquat_intel,
                keep_download=args.keep_download,
                as_json=args.json,
                history_dir=args.history_dir,
                verbose=args.verbose,
            )
        )


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli.py -v`
Expected: PASS, all tests (the 4 fixed in Step 1, plus the rest from the typosquat-metadata-signals and output-persistence plans, which call `_analyse_one`/`_run_analyze` directly and are unaffected by the subcommand restructure).

Run: `uv run pytest tests/ -v`
Expected: full suite PASS.

Run: `uv run ruff check nidhogg/cli.py && uv run mypy nidhogg/cli.py`
Expected: no errors. If `ruff` flags the file length or argument count (`PLR0913`, `C901`, `PLR0915`) on `_build_parser` or `main`, add a `# noqa` with the specific code to that function's `def` line rather than restructuring — this mirrors the existing `# noqa: PLR0913` precedent already on `_run_analyze`/`_run_batch`.

- [ ] **Step 5: Commit**

```bash
git add nidhogg/cli.py tests/test_cli.py
git commit -m "feat(cli)!: split into analyze/fetch/monitor subcommands

BREAKING CHANGE: 'nidhogg <path>' no longer works; use 'nidhogg analyze <path>'."
```

---

### Task 5: `fetch` subcommand tests

**Files:**
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `_run_fetch` (Task 4).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_cli.py`:

```python
from nidhogg.cli import _run_fetch
from nidhogg.fetching.pypi_fetch import DownloadInfo


def test_run_fetch_analyses_downloaded_package(tmp_path: Path):
    extracted = tmp_path / "extracted"
    (extracted / "pkg").mkdir(parents=True)
    (extracted / "pkg" / "module.py").write_text("x = 1", encoding="utf-8")

    from contextlib import contextmanager

    @contextmanager
    def _fake_fetched_package(name, version=None, *, keep=False, keep_dir=None):  # noqa: ANN001, ARG001
        yield extracted

    with patch(
        "nidhogg.fetching.pypi_fetch.fetched_package", _fake_fetched_package
    ):
        exit_code = _run_fetch(
            "somepkg",
            None,
            None,
            as_json=False,
            verbose=False,
            check_urls=True,
            check_typosquat=False,
            typosquat_intel=True,
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
            check_urls=True,
            check_typosquat=True,
            typosquat_intel=True,
            keep_download=None,
            history_dir=None,
        )
    assert exit_code == 2


def test_run_fetch_writes_history(tmp_path: Path):
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    history_dir = tmp_path / "history"

    from contextlib import contextmanager

    @contextmanager
    def _fake_fetched_package(name, version=None, *, keep=False, keep_dir=None):  # noqa: ANN001, ARG001
        yield extracted

    with patch(
        "nidhogg.fetching.pypi_fetch.fetched_package", _fake_fetched_package
    ):
        _run_fetch(
            "somepkg",
            None,
            None,
            as_json=False,
            verbose=False,
            check_urls=True,
            check_typosquat=False,
            typosquat_intel=True,
            keep_download=None,
            history_dir=history_dir,
        )
    assert len(list(history_dir.glob("*.jsonl"))) == 1
```

Add `from nidhogg.core.exceptions import PackageReadError` to the top of `tests/test_cli.py` if not already imported.

- [ ] **Step 2: Run tests to verify they pass**

`_run_fetch` was already fully implemented in Task 4, Step 3 — this task only adds coverage for it, so there is no red step.

Run: `uv run pytest tests/test_cli.py -v`
Expected: PASS, all tests.

- [ ] **Step 3: Commit**

```bash
git add tests/test_cli.py
git commit -m "test(cli): cover fetch subcommand dispatch"
```

---

### Task 6: `monitor` subcommand tests

**Files:**
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `_run_monitor`, `_analyse_new_package` (Task 4).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_cli.py`:

```python
from nidhogg.cli import _run_monitor
from nidhogg.fetching.changelog import ChangelogEntry
from nidhogg.fetching.monitor_state import MonitorState, load_state


def test_run_monitor_processes_one_batch_then_stops(tmp_path: Path):
    """KeyboardInterrupt after the first iteration exits the loop cleanly."""
    index_file = tmp_path / "state.json"
    fake_client = MagicMock()
    fake_client.current_serial.side_effect = [100, 100]
    fake_client.entries_since.return_value = [
        ChangelogEntry(name="newpkg", version="", timestamp=1, action="create", serial=99)
    ]

    fake_analysis = PackageAnalysis(name="newpkg", path=tmp_path)

    def _fake_analyse_new_package(name, **kwargs):  # noqa: ANN001, ARG001
        return fake_analysis, Verdict.CLEAN

    def _fake_sleep(seconds):  # noqa: ANN001, ARG001
        raise KeyboardInterrupt

    with (
        patch(
            "nidhogg.fetching.changelog.ChangelogClient", return_value=fake_client
        ),
        patch("nidhogg.cli._analyse_new_package", _fake_analyse_new_package),
        patch("time.sleep", _fake_sleep),
    ):
        exit_code = _run_monitor(
            interval=0,
            index_file=index_file,
            concurrency=2,
            check_urls=True,
            check_typosquat=True,
            typosquat_intel=True,
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
    from nidhogg.fetching.monitor_state import save_state

    save_state(index_file, MonitorState(last_serial=500))

    fake_client = MagicMock()
    fake_client.current_serial.return_value = 500
    fake_client.entries_since.return_value = []

    def _fake_sleep(seconds):  # noqa: ANN001, ARG001
        raise KeyboardInterrupt

    with (
        patch(
            "nidhogg.fetching.changelog.ChangelogClient", return_value=fake_client
        ),
        patch("time.sleep", _fake_sleep),
    ):
        _run_monitor(
            interval=0,
            index_file=index_file,
            concurrency=2,
            check_urls=True,
            check_typosquat=True,
            typosquat_intel=True,
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
        ChangelogEntry(name="badpkg", version="", timestamp=1, action="create", serial=1),
        ChangelogEntry(name="goodpkg", version="", timestamp=2, action="create", serial=2),
    ]

    fake_analysis = PackageAnalysis(name="goodpkg", path=tmp_path)

    def _fake_analyse_new_package(name, **kwargs):  # noqa: ANN001, ARG001
        if name == "badpkg":
            raise PackageReadError("network error")
        return fake_analysis, Verdict.CLEAN

    def _fake_sleep(seconds):  # noqa: ANN001, ARG001
        raise KeyboardInterrupt

    with (
        patch(
            "nidhogg.fetching.changelog.ChangelogClient", return_value=fake_client
        ),
        patch("nidhogg.cli._analyse_new_package", _fake_analyse_new_package),
        patch("time.sleep", _fake_sleep),
    ):
        exit_code = _run_monitor(
            interval=0,
            index_file=index_file,
            concurrency=2,
            check_urls=True,
            check_typosquat=True,
            typosquat_intel=True,
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

Add these imports to the top of `tests/test_cli.py`:

```python
from unittest.mock import MagicMock, patch

from nidhogg.classifier import Verdict
from nidhogg.core.models import PackageAnalysis
```

(`MagicMock`/`patch` may already be partially imported from earlier tasks — merge with the existing `from unittest.mock import ...` line rather than duplicating it.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cli.py -k run_monitor -v`
Expected: FAIL — before this task, `_run_monitor` and `_analyse_new_package` don't exist yet if Task 4 hasn't run, or (if Task 4 already ran) some assertions may already pass. Either way, run once to confirm the new tests actually exercise real behavior rather than trivially passing.

- [ ] **Step 3: Implement**

No implementation changes needed. `_run_monitor` already does `from nidhogg.fetching.changelog import ChangelogClient` as a *deferred* import inside the function body (Task 4) — this reads the `ChangelogClient` attribute off the `nidhogg.fetching.changelog` module at call time, so patching `"nidhogg.fetching.changelog.ChangelogClient"` (the source module, not `nidhogg.cli`) is picked up correctly, the same pattern already used for `check_typosquatting`/`enrich_typosquat` elsewhere in this codebase (see `tests/test_cli.py`'s existing tests from the typosquat-metadata-signals plan). `_analyse_new_package` is a real module-level function in `nidhogg/cli.py` itself, so `patch("nidhogg.cli._analyse_new_package", ...)` works directly — no deferred-import subtlety there.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli.py -v`
Expected: PASS, all tests.

Run: `uv run pytest tests/ -v`
Expected: full suite PASS.

Run: `uv run ruff check nidhogg/cli.py && uv run mypy nidhogg/cli.py`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add tests/test_cli.py
git commit -m "test(cli): cover monitor subcommand loop, resume, and per-package failure handling"
```

---

### Task 7: Update `CLAUDE.md`

**Files:**
- Modify: `CLAUDE.md`

**Interfaces:** None (documentation only).

- [ ] **Step 1: Update the architecture section**

In `CLAUDE.md`, in the "Contexto del proyecto" section, add a paragraph after the existing description:

```markdown
Además del flujo principal (carpetas ya extraídas por un downloader externo),
Nidhogg incluye un fetcher propio y aislado (`nidhogg/fetching/`) para dos
casos de uso específicos: analizar un paquete puntual bajo demanda
(`nidhogg fetch <nombre>`) y vigilar altas nuevas en PyPI en tiempo real
(`nidhogg monitor`). Este fetcher no sustituye ni depende del downloader
externo del flujo batch — son mecanismos de descubrimiento distintos para
casos de uso distintos.
```

In the "Arquitectura" section's directory tree, add the new package after `cli.py`:

```
├── fetching/
│   ├── pypi_fetch.py      # Descarga + extracción segura de paquetes PyPI
│   ├── changelog.py       # Cliente del changelog XML-RPC de PyPI
│   └── monitor_state.py   # Persistencia del último serial procesado
```

Update the line describing the CLI entry point to mention subcommands:

```markdown
El pipeline es siempre: `walker → [layer1, layer2] → aggregator → enrichment → classifier → output`.
Las capas 1 y 2 se ejecutan en paralelo sobre cada archivo `.py`.

La CLI (`nidhogg`) expone tres subcomandos: `analyze` (flujo principal sobre
una carpeta ya extraída), `fetch` (descarga un paquete puntual de PyPI y lo
analiza) y `monitor` (vigila altas nuevas en PyPI y analiza cada una). `fetch`
y `monitor` usan el fetcher propio en `nidhogg/fetching/`, no el downloader
externo.
```

- [ ] **Step 2: No automated test** — this is a documentation-only change; verify by reading the updated file.

Run: `git diff CLAUDE.md` and confirm the changes read correctly.

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document the fetching/ package and analyze/fetch/monitor subcommands"
```

---

## Final Verification

- [ ] Run the complete suite once more: `uv run pytest tests/ -v`
- [ ] Run `uv run ruff check .` and `uv run ruff format --check .`
- [ ] Run `uv run mypy nidhogg/`
- [ ] Manually smoke-test (requires network): `uv run nidhogg fetch requests --no-check-urls` downloads and typosquat-checks the real `requests` package (expect a clean result, since it IS the real package); `uv run nidhogg analyze <any extracted dir>` still works under the new subcommand.
- [ ] Manually smoke-test `nidhogg monitor --interval 5` for a few iterations, confirm it prints newly published packages and that `~/.cache/nidhogg/monitor_state.json` is created and updated; stop with Ctrl+C and confirm it exits cleanly.
