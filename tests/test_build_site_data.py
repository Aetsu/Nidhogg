"""Tests for scripts/build_site_data.py."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from build_site_data import build_day_document, build_site_data


def _write_jsonl(path: Path, documents: list[dict]) -> None:
    path.write_text(
        "\n".join(json.dumps(doc) for doc in documents) + "\n", encoding="utf-8"
    )


def _document(
    name: str,
    tags: list[str],
    version: str | None = None,
    download_url: str | None = None,
) -> dict:
    return {
        "analyzed_at": "2026-07-17T10:00:00+00:00",
        "package": {
            "name": name,
            "path": "/tmp/pkg",  # noqa: S108
            "version": version,
            "download_url": download_url,
        },
        "summary": {"total_findings": 1, "total_files": 1},
        "files": [
            {
                "file": "setup.py",
                "tags": ["packaging"],
                "findings": [
                    {
                        "url": "http://evil.example/payload",
                        "line": 42,
                        "layer": "ast",
                        "tags": tags,
                        "cert_issuer": None,
                        "http_status": None,
                        "http_title": None,
                    }
                ],
            }
        ],
    }


def test_build_day_document_flattens_findings_and_picks_method_and_threat(
    tmp_path: Path,
):
    jsonl_path = tmp_path / "2026-07-17.jsonl"
    _write_jsonl(jsonl_path, [_document("evilpkg", ["via_base64", "exfiltration"])])

    document = build_day_document(jsonl_path)

    assert document["stats"] == {"total_packages": 1, "malicious": 1, "clean": 0}
    package = document["packages"][0]
    assert package["name"] == "evilpkg"
    assert package["analyzed_at"] == "2026-07-17T10:00:00+00:00"
    finding = package["findings"][0]
    assert finding["file"] == "setup.py"
    assert finding["method"] == "via_base64"
    assert finding["domain_threat"] == "exfiltration"


def test_build_day_document_carries_package_version(tmp_path: Path):
    jsonl_path = tmp_path / "2026-07-17.jsonl"
    _write_jsonl(jsonl_path, [_document("evilpkg", ["via_base64"], version="1.2.3")])

    document = build_day_document(jsonl_path)

    assert document["packages"][0]["version"] == "1.2.3"


def test_build_day_document_version_none_when_unknown(tmp_path: Path):
    jsonl_path = tmp_path / "2026-07-17.jsonl"
    _write_jsonl(jsonl_path, [_document("cleanpkg", [])])

    document = build_day_document(jsonl_path)

    assert document["packages"][0]["version"] is None


def test_build_day_document_carries_package_download_url(tmp_path: Path):
    jsonl_path = tmp_path / "2026-07-17.jsonl"
    _write_jsonl(
        jsonl_path,
        [
            _document(
                "evilpkg",
                ["via_base64"],
                version="1.2.3",
                download_url="https://files.pythonhosted.org/pkg-1.2.3.tar.gz",
            )
        ],
    )

    document = build_day_document(jsonl_path)

    assert (
        document["packages"][0]["download_url"]
        == "https://files.pythonhosted.org/pkg-1.2.3.tar.gz"
    )


def test_build_day_document_clean_package_has_no_domain_threat(tmp_path: Path):
    jsonl_path = tmp_path / "2026-07-17.jsonl"
    _write_jsonl(jsonl_path, [_document("cleanpkg", ["via_concat"])])

    document = build_day_document(jsonl_path)

    assert document["stats"] == {"total_packages": 1, "malicious": 0, "clean": 1}
    assert document["packages"][0]["findings"][0]["domain_threat"] is None


def test_build_day_document_orders_packages_most_recent_first(tmp_path: Path):
    jsonl_path = tmp_path / "2026-07-17.jsonl"
    older = {**_document("pkg-a", []), "analyzed_at": "2026-07-17T09:00:00+00:00"}
    newer = {**_document("pkg-b", []), "analyzed_at": "2026-07-17T11:00:00+00:00"}
    _write_jsonl(jsonl_path, [older, newer])

    document = build_day_document(jsonl_path)

    assert [pkg["name"] for pkg in document["packages"]] == ["pkg-b", "pkg-a"]


def test_build_site_data_writes_one_file_per_day_and_an_index(tmp_path: Path):
    history_dir = tmp_path / "history"
    history_dir.mkdir()
    _write_jsonl(history_dir / "2026-07-16.jsonl", [_document("pkg-a", [])])
    _write_jsonl(history_dir / "2026-07-17.jsonl", [_document("pkg-b", [])])

    site_data_dir = tmp_path / "site-data"
    dates = build_site_data(history_dir, site_data_dir)

    assert dates == ["2026-07-17", "2026-07-16"]
    assert (site_data_dir / "2026-07-16.json").exists()
    assert (site_data_dir / "2026-07-17.json").exists()

    index = json.loads((site_data_dir / "index.json").read_text(encoding="utf-8"))
    assert index["latest"] == "2026-07-17"
    assert index["dates"] == ["2026-07-17", "2026-07-16"]


def test_build_site_data_empty_history_writes_empty_index(tmp_path: Path):
    history_dir = tmp_path / "history"
    history_dir.mkdir()
    site_data_dir = tmp_path / "site-data"

    dates = build_site_data(history_dir, site_data_dir)

    assert dates == []
    index = json.loads((site_data_dir / "index.json").read_text(encoding="utf-8"))
    assert index == {"generated_at": index["generated_at"], "latest": None, "dates": []}


def _binary_document(package: str, binaries: list[dict]) -> dict:
    return {
        "analyzed_at": "2026-07-19T10:00:00+00:00",
        "package": {
            "name": package,
            "path": "/tmp/pkg",  # noqa: S108
            "version": None,
            "download_url": None,
        },
        "summary": {
            "total_binaries": len(binaries),
            "signed": sum(1 for b in binaries if b["signed"]),
        },
        "binaries": binaries,
    }


def test_build_day_document_includes_binaries_when_present(tmp_path: Path):
    jsonl_path = tmp_path / "2026-07-19.jsonl"
    _write_jsonl(jsonl_path, [_document("cleanpkg", [])])
    binaries_jsonl_path = tmp_path / "binaries-2026-07-19.jsonl"
    _write_jsonl(
        binaries_jsonl_path,
        [
            _binary_document(
                "evilpkg",
                [
                    {
                        "name": "helper.dll",
                        "file": "native/helper.dll",
                        "sha256": "a" * 64,
                        "format": "pe",
                        "signed": True,
                        "signer": "CN=Example Corp",
                    }
                ],
            )
        ],
    )

    document = build_day_document(jsonl_path, binaries_jsonl_path)

    assert len(document["binaries"]) == 1
    group = document["binaries"][0]
    assert group["package"] == "evilpkg"
    assert group["binaries"][0]["name"] == "helper.dll"


def test_build_day_document_binaries_empty_when_not_provided(tmp_path: Path):
    jsonl_path = tmp_path / "2026-07-19.jsonl"
    _write_jsonl(jsonl_path, [_document("cleanpkg", [])])

    document = build_day_document(jsonl_path)

    assert document["binaries"] == []


def test_build_site_data_reads_binaries_subdir(tmp_path: Path):
    history_dir = tmp_path / "history"
    history_dir.mkdir()
    _write_jsonl(history_dir / "2026-07-19.jsonl", [_document("pkg-a", [])])
    binaries_dir = history_dir / "binaries"
    binaries_dir.mkdir()
    _write_jsonl(
        binaries_dir / "2026-07-19.jsonl",
        [
            _binary_document(
                "pkg-a",
                [
                    {
                        "name": "x.so",
                        "file": "x.so",
                        "sha256": "b" * 64,
                        "format": "elf",
                        "signed": False,
                        "signer": None,
                    }
                ],
            )
        ],
    )

    site_data_dir = tmp_path / "site-data"
    build_site_data(history_dir, site_data_dir)

    day_doc = json.loads(
        (site_data_dir / "2026-07-19.json").read_text(encoding="utf-8")
    )
    assert len(day_doc["binaries"]) == 1
    assert day_doc["binaries"][0]["binaries"][0]["name"] == "x.so"


def test_build_site_data_no_binaries_subdir_is_empty(tmp_path: Path):
    history_dir = tmp_path / "history"
    history_dir.mkdir()
    _write_jsonl(history_dir / "2026-07-19.jsonl", [_document("pkg-a", [])])

    site_data_dir = tmp_path / "site-data"
    build_site_data(history_dir, site_data_dir)

    day_doc = json.loads(
        (site_data_dir / "2026-07-19.json").read_text(encoding="utf-8")
    )
    assert day_doc["binaries"] == []
