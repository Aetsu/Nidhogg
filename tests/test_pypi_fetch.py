"""Tests for fetching/pypi_fetch.py."""

from __future__ import annotations

import io
import tarfile
import tempfile
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
    "info": {"version": "1.0"},
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
    ],
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
    assert info.version == "1.0"


def test_resolve_download_info_falls_back_to_wheel():
    payload = {"urls": [_PYPI_URLS_PAYLOAD["urls"][0]]}
    with patch(
        "nidhogg.fetching.pypi_fetch._fetch_pypi_urls_json", return_value=payload
    ):
        info = resolve_download_info("pkg")
    assert info.packagetype == "bdist_wheel"


def test_resolve_download_info_raises_when_no_files():
    with (
        patch(
            "nidhogg.fetching.pypi_fetch._fetch_pypi_urls_json",
            return_value={"urls": []},
        ),
        pytest.raises(PackageReadError),
    ):
        resolve_download_info("pkg")


def test_resolve_download_info_raises_on_network_error():
    import urllib.error

    with (
        patch(
            "nidhogg.fetching.pypi_fetch._fetch_pypi_urls_json",
            side_effect=urllib.error.URLError("boom"),
        ),
        pytest.raises(PackageReadError),
    ):
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


def test_safe_extract_tar_raises_package_read_error_on_corrupt_archive(
    tmp_path: Path,
):
    archive = tmp_path / "corrupt.tar.gz"
    archive.write_bytes(b"not a real archive")
    dest = tmp_path / "extracted"
    dest.mkdir()
    with pytest.raises(PackageReadError):
        _safe_extract_tar(archive, dest)


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


def test_safe_extract_zip_raises_package_read_error_on_corrupt_archive(
    tmp_path: Path,
):
    archive = tmp_path / "corrupt.zip"
    archive.write_bytes(b"not a real archive")
    dest = tmp_path / "extracted"
    dest.mkdir()
    with pytest.raises(PackageReadError):
        _safe_extract_zip(archive, dest)


def test_download_and_extract_downloads_and_extracts(tmp_path: Path):  # noqa: ARG001
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
                version="1.0",
            ),
        ),
        patch(
            "nidhogg.fetching.pypi_fetch.urllib.request.urlretrieve",
            side_effect=_fake_urlretrieve,
        ),
    ):
        result, resolved_version, download_url = download_and_extract("pkg")

    assert (result / "pkg-1.0" / "setup.py").exists()
    assert resolved_version == "1.0"
    assert download_url == "https://example.com/pkg-1.0.tar.gz"


def test_download_and_extract_cleans_up_temp_dir_on_corrupt_archive(
    tmp_path: Path,
):
    def _fake_urlretrieve(url: str, filename: str) -> tuple[str, object]:  # noqa: ARG001
        Path(filename).write_bytes(b"not a real archive")
        return filename, None

    created_dirs: list[Path] = []
    real_mkdtemp = tempfile.mkdtemp

    def _fake_mkdtemp(*, prefix: str | None = None) -> str:
        created = real_mkdtemp(prefix=prefix, dir=tmp_path)
        created_dirs.append(Path(created))
        return created

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
        patch(
            "nidhogg.fetching.pypi_fetch.tempfile.mkdtemp",
            side_effect=_fake_mkdtemp,
        ),
        pytest.raises(PackageReadError),
    ):
        download_and_extract("pkg")

    assert created_dirs, "expected tempfile.mkdtemp to have been called"
    assert not created_dirs[0].exists()


def test_fetched_package_cleans_up_by_default(tmp_path: Path):  # noqa: ARG001
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
                version="1.0",
            ),
        ),
        patch(
            "nidhogg.fetching.pypi_fetch.urllib.request.urlretrieve",
            side_effect=_fake_urlretrieve,
        ),
    ):
        with fetched_package("pkg") as (path, resolved_version, download_url):
            assert path.exists()
            assert resolved_version == "1.0"
            assert download_url == "https://example.com/pkg-1.0.tar.gz"
        assert not path.exists()


def test_fetched_package_keeps_when_requested(tmp_path: Path):  # noqa: ARG001
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
        with fetched_package("pkg", keep=True) as (path, _resolved_version, _url):
            kept_path = path
        assert kept_path.exists()
