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
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from loguru import logger

if TYPE_CHECKING:
    from collections.abc import Iterator

from nidhogg.core.exceptions import PackageReadError

_REQUEST_TIMEOUT = 10.0


@dataclass(frozen=True)
class DownloadInfo:
    """Resolved download location for a package release.

    Attributes:
        url: Direct download URL for the archive.
        filename: Archive filename, used to pick the extraction strategy.
        packagetype: PyPI's package type label (``"sdist"`` or ``"bdist_wheel"``).
        version: The concrete version PyPI resolved (e.g. ``"latest"`` becomes
            the actual release number). Empty string if the API response
            didn't carry version info.
    """

    url: str
    filename: str
    packagetype: str
    version: str = ""


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
        version=str(payload.get("info", {}).get("version", "")),
    )


def _safe_extract_tar(archive_path: Path, dest: Path) -> None:
    """Extract a tar(.gz) archive, rejecting path traversal and unsafe members.

    Args:
        archive_path: Path to the ``.tar``/``.tar.gz`` archive.
        dest: Directory to extract into.

    Raises:
        PackageReadError: If a member would extract outside *dest*, or if the
            archive cannot be opened or read (e.g. truncated or corrupt).
    """
    try:
        with tarfile.open(archive_path) as tf:
            try:
                tf.extractall(dest, filter="data")
            except tarfile.FilterError as exc:
                msg = f"Unsafe path in archive {archive_path.name!r}: {exc}"
                raise PackageReadError(msg) from exc
    except tarfile.TarError as exc:
        msg = f"Could not read archive {archive_path.name!r}: {exc}"
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
        PackageReadError: If a member would extract outside *dest*, or if the
            archive cannot be opened or read (e.g. truncated or corrupt).
    """
    resolved_dest = dest.resolve()
    try:
        with zipfile.ZipFile(archive_path) as zf:
            for member in zf.infolist():
                target = (dest / member.filename).resolve()
                if not target.is_relative_to(resolved_dest):
                    msg = (
                        f"Unsafe path in archive {archive_path.name!r}: "
                        f"{member.filename!r}"
                    )
                    raise PackageReadError(msg)
            zf.extractall(dest)  # noqa: S202 -- members validated above
    except zipfile.BadZipFile as exc:
        msg = f"Could not read archive {archive_path.name!r}: {exc}"
        raise PackageReadError(msg) from exc


def download_and_extract(
    name: str, version: str | None = None
) -> tuple[Path, str, str]:
    """Download *name* from PyPI and extract it to a fresh temporary directory.

    Args:
        name: Package name to download.
        version: Specific version, or ``None`` for the latest release.

    Returns:
        A tuple of: the directory containing the extracted contents (the
        caller is responsible for cleaning it up, see :func:`fetched_package`);
        the concrete version PyPI resolved (never empty in practice, but see
        :attr:`DownloadInfo.version`); and the archive's direct download URL
        (used to link to the exact distribution on inspector.pypi.io).

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

    is_tar = info.filename.endswith((".tar.gz", ".tgz"))
    is_zip = info.filename.endswith((".zip", ".whl"))
    if not (is_tar or is_zip):
        shutil.rmtree(tmp_dir, ignore_errors=True)
        msg = f"Unsupported archive format: {info.filename!r}"
        raise PackageReadError(msg)

    extract_dir = tmp_dir / "extracted"
    extract_dir.mkdir()
    try:
        if is_tar:
            _safe_extract_tar(archive_path, extract_dir)
        else:
            _safe_extract_zip(archive_path, extract_dir)
    except PackageReadError:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise

    return extract_dir, info.version, info.url


@contextmanager
def fetched_package(
    name: str,
    version: str | None = None,
    *,
    keep: bool = False,
    keep_dir: Path | None = None,
) -> Iterator[tuple[Path, str, str]]:
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
        A tuple of the extracted package directory, the concrete version
        PyPI resolved, and the archive's direct download URL.
    """
    extract_dir, resolved_version, download_url = download_and_extract(name, version)
    try:
        yield extract_dir, resolved_version, download_url
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
