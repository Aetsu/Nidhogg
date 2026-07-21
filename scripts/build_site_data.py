#!/usr/bin/env python3
"""Aggregate Nidhogg's per-package history into per-day JSON for the site.

Reads ``history/*.jsonl`` (one line per analysed package, written by
``nidhogg/output/history.py``) and writes one ``site/data/YYYY-MM-DD.json``
per day plus a ``site/data/index.json`` listing the available dates. Each
``*.jsonl`` file is already a single day's worth of runs, so the transform
is 1:1 per file — no cross-day merge or dedup involved.

Usage:
    uv run python scripts/build_site_data.py <history_dir> <site_data_dir>
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_METHOD_TAGS = {
    "via_base64",
    "via_concat",
    "via_fstring",
    "via_scope",
    "via_decoded",
    "raw_ip",
}
_THREAT_TAGS = {
    "shortener",
    "tunneling",
    "exfiltration",
    "ip_recon",
    "malware_hosting",
    "suspicious_tld",
    "punycode",
}
_MIN_REPEAT_OFFENDER_DAYS = 2


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(UTC).isoformat()


def _pick_tag(tags: list[str], candidates: set[str]) -> str | None:
    """Return the first tag in *tags* found in *candidates*, or ``None``.

    Args:
        tags: A finding's sorted tag list (extraction-method and/or threat
            tags mixed together, per ``nidhogg/analysis/aggregator.py``).
        candidates: The subset of tag values to look for.

    Returns:
        The first matching tag, or ``None`` if none of *tags* is in
        *candidates*.
    """
    return next((t for t in tags if t in candidates), None)


def _flatten_findings(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten a history document's per-file findings into the site's schema.

    Args:
        document: One parsed line from a ``history/*.jsonl`` file — the
            ``build_document()`` shape (``package``/``summary``/``files``).

    Returns:
        A flat list of finding dicts, each carrying its source file, method,
        and domain threat alongside the original finding fields.
    """
    return [
        {
            "url": finding["url"],
            "file": file_entry["file"],
            "line": finding["line"],
            "layer": finding["layer"],
            "method": _pick_tag(finding["tags"], _METHOD_TAGS),
            "domain_threat": _pick_tag(finding["tags"], _THREAT_TAGS),
            "http_status": finding.get("http_status"),
            "http_title": finding.get("http_title"),
            "cert_issuer": finding.get("cert_issuer"),
        }
        for file_entry in document["files"]
        for finding in file_entry["findings"]
    ]


def _to_site_package(document: dict[str, Any]) -> dict[str, Any]:
    """Convert one history document into the site's per-package entry.

    Args:
        document: One parsed line from a ``history/*.jsonl`` file, stamped
            with ``analyzed_at`` by ``append_finding``.

    Returns:
        A dict matching the ``packages[]`` entries the site's ``app.js``
        expects.
    """
    return {
        "name": document["package"]["name"],
        "version": document["package"].get("version"),
        "download_url": document["package"].get("download_url"),
        "analyzed_at": document["analyzed_at"],
        "total_findings": document["summary"]["total_findings"],
        "findings": _flatten_findings(document),
    }


def _to_site_binary_group(document: dict[str, Any]) -> dict[str, Any]:
    """Convert one binaries-history document into the site's per-package entry.

    Args:
        document: One parsed line from a ``history/binaries/*.jsonl`` file,
            stamped with ``analyzed_at`` by ``append_binary_finding``.

    Returns:
        A dict with the package name, analysis timestamp, and its list of
        binary entries (already in the site's schema — see
        ``build_binaries_document`` in ``nidhogg/output/writer.py``).
    """
    return {
        "package": document["package"]["name"],
        "version": document["package"].get("version"),
        "analyzed_at": document["analyzed_at"],
        "binaries": document["binaries"],
    }


def _to_site_install_hook_group(document: dict[str, Any]) -> dict[str, Any]:
    """Convert one install-hooks-history document into the site's per-package entry.

    Args:
        document: One parsed line from a ``history/install_hooks/*.jsonl``
            file, stamped with ``analyzed_at`` by
            ``append_install_hook_finding``.

    Returns:
        A dict with the package name, version, download URL, analysis
        timestamp, and its list of install-hook entries (already in the
        site's schema — see ``build_install_hooks_document`` in
        ``nidhogg/output/writer.py``).
    """
    return {
        "package": document["package"]["name"],
        "version": document["package"].get("version"),
        "download_url": document["package"].get("download_url"),
        "analyzed_at": document["analyzed_at"],
        "install_hooks": document["install_hooks"],
    }


def _record_package_day(
    pkg: dict[str, Any],
    date: str,
    domain_counts: dict[str, dict[str, Any]],
    package_history: dict[str, dict[str, Any]],
) -> None:
    """Fold one package's findings for *date* into the running rollups.

    Args:
        pkg: One entry from a day document's ``packages`` list.
        date: The day this package was analyzed on (``YYYY-MM-DD``).
        domain_counts: Mutated in place — maps domain to
            ``{"count": int, "threats": Counter}`` across all threat-tagged
            findings seen so far.
        package_history: Mutated in place — maps package name to
            ``{"dates": set[str], "total_findings": int}`` across all days
            seen so far. ``dates`` holds only days the package was
            malicious on.
    """
    history = package_history.setdefault(
        pkg["name"], {"dates": set(), "total_findings": 0}
    )
    history["total_findings"] += pkg["total_findings"]

    is_malicious_today = False
    for finding in pkg["findings"]:
        threat = finding["domain_threat"]
        if not threat:
            continue
        is_malicious_today = True
        domain = urlsplit(finding["url"]).netloc
        if not domain:
            continue
        domain_entry = domain_counts.setdefault(
            domain, {"count": 0, "threats": Counter()}
        )
        domain_entry["count"] += 1
        domain_entry["threats"][threat] += 1

    if is_malicious_today:
        history["dates"].add(date)


def _top_domains(domain_counts: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Top 10 domains by threat-tagged finding count, each with its top threat tag.

    Args:
        domain_counts: As accumulated by ``_record_package_day``.

    Returns:
        Up to 10 ``{"domain", "count", "threat"}`` dicts, sorted by count
        descending. ``threat`` is the most frequent ``domain_threat`` value
        seen for that domain.
    """
    ranked = sorted(domain_counts.items(), key=lambda kv: kv[1]["count"], reverse=True)
    return [
        {
            "domain": domain,
            "count": data["count"],
            "threat": data["threats"].most_common(1)[0][0],
        }
        for domain, data in ranked[:10]
    ]


def _repeat_offenders(
    package_history: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Packages malicious on 2+ distinct days, ranked by recurrence then volume.

    Args:
        package_history: As accumulated by ``_record_package_day``.

    Returns:
        ``{"name", "days_seen", "total_findings", "first_seen", "last_seen"}``
        dicts, sorted by ``days_seen`` descending then ``total_findings``
        descending. Packages malicious on 0 or 1 day are excluded.
    """
    candidates = (
        {
            "name": name,
            "days_seen": len(history["dates"]),
            "total_findings": history["total_findings"],
            "first_seen": min(history["dates"]),
            "last_seen": max(history["dates"]),
        }
        for name, history in package_history.items()
        if len(history["dates"]) >= _MIN_REPEAT_OFFENDER_DAYS
    )
    return sorted(
        candidates, key=lambda entry: (-entry["days_seen"], -entry["total_findings"])
    )


def build_trends_document(
    day_documents: list[tuple[str, dict[str, Any]]],
) -> dict[str, Any]:
    """Roll up per-day site documents into a cross-day trends summary.

    Args:
        day_documents: ``(date, document)`` pairs, one per history day,
            ``document`` in the same shape ``build_day_document`` returns.
            Order doesn't matter — the result is sorted internally.

    Returns:
        A dict with ``generated_at``, ``daily`` (ascending by date),
        ``top_domains`` (top 10, threat-tagged findings only), and
        ``repeat_offenders`` (packages malicious on 2+ distinct days) — the
        shape ``site/data/trends.json`` is written in.
    """
    ordered = sorted(day_documents, key=lambda pair: pair[0])

    daily: list[dict[str, Any]] = []
    domain_counts: dict[str, dict[str, Any]] = {}
    package_history: dict[str, dict[str, Any]] = {}

    for date, document in ordered:
        packages = document["packages"]
        daily.append(
            {
                "date": date,
                "total_packages": document["stats"]["total_packages"],
                "malicious_packages": document["stats"]["malicious"],
                "total_findings": sum(pkg["total_findings"] for pkg in packages),
            }
        )
        for pkg in packages:
            _record_package_day(pkg, date, domain_counts, package_history)

    return {
        "generated_at": _now_iso(),
        "daily": daily,
        "top_domains": _top_domains(domain_counts),
        "repeat_offenders": _repeat_offenders(package_history),
    }


def build_day_binaries(jsonl_path: Path) -> list[dict[str, Any]]:
    """Build the site's per-day binaries list from one history JSONL file.

    Args:
        jsonl_path: Path to a single day's ``binaries/*.jsonl`` file.

    Returns:
        One entry per analysed package that had binaries that day, in file
        order. Empty list if *jsonl_path* does not exist.
    """
    if not jsonl_path.exists():
        return []
    return [_to_site_binary_group(doc) for doc in _read_jsonl(jsonl_path)]


def build_day_install_hooks(jsonl_path: Path) -> list[dict[str, Any]]:
    """Build the site's per-day install-hooks list from one history JSONL file.

    Args:
        jsonl_path: Path to a single day's ``install_hooks/*.jsonl`` file.

    Returns:
        One entry per analysed package that had install-hook findings that
        day, in file order. Empty list if *jsonl_path* does not exist.
    """
    if not jsonl_path.exists():
        return []
    return [_to_site_install_hook_group(doc) for doc in _read_jsonl(jsonl_path)]


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Parse each non-blank line of *path* as a JSON document."""
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def build_day_document(
    jsonl_path: Path,
    binaries_jsonl_path: Path | None = None,
    install_hooks_jsonl_path: Path | None = None,
) -> dict[str, Any]:
    """Build the site's per-day document from one ``history/*.jsonl`` file.

    Args:
        jsonl_path: Path to a single day's URL-findings history file.
        binaries_jsonl_path: Path to the matching day's binaries history
            file (``history/binaries/YYYY-MM-DD.jsonl``), or ``None`` if it
            doesn't exist — the resulting ``"binaries"`` key is an empty
            list in that case.
        install_hooks_jsonl_path: Path to the matching day's install-hooks
            history file (``history/install_hooks/YYYY-MM-DD.jsonl``), or
            ``None`` if it doesn't exist — the resulting ``"install_hooks"``
            key is an empty list in that case.

    Returns:
        A dict with ``generated_at``, ``stats``, ``packages``, ``binaries``,
        and ``install_hooks`` — the same shape the site's ``app.js`` already
        consumes, scoped to this one day.
    """
    packages = sorted(
        (_to_site_package(doc) for doc in _read_jsonl(jsonl_path)),
        key=lambda pkg: pkg["analyzed_at"],
        reverse=True,
    )
    malicious = sum(
        1 for pkg in packages if any(f["domain_threat"] for f in pkg["findings"])
    )
    binaries = build_day_binaries(binaries_jsonl_path) if binaries_jsonl_path else []
    install_hooks = (
        build_day_install_hooks(install_hooks_jsonl_path)
        if install_hooks_jsonl_path
        else []
    )
    return {
        "generated_at": _now_iso(),
        "stats": {
            "total_packages": len(packages),
            "malicious": malicious,
            "clean": len(packages) - malicious,
        },
        "packages": packages,
        "binaries": binaries,
        "install_hooks": install_hooks,
    }


def build_site_data(history_dir: Path, site_data_dir: Path) -> list[str]:
    """Rebuild every per-day JSON plus the index and trends under *site_data_dir*.

    Reprocesses every ``history/*.jsonl`` file on each call — cheap given
    per-day file sizes, and avoids keeping incremental state to maintain.

    Args:
        history_dir: Directory containing ``history/*.jsonl`` files.
        site_data_dir: Directory to write ``YYYY-MM-DD.json`` +
            ``index.json`` + ``trends.json`` into. Created if missing.

    Returns:
        The dates written, sorted descending (most recent first).
    """
    site_data_dir.mkdir(parents=True, exist_ok=True)

    dates: list[str] = []
    day_documents: list[tuple[str, dict[str, Any]]] = []
    for jsonl_path in sorted(history_dir.glob("*.jsonl")):
        date = jsonl_path.stem
        binaries_jsonl_path = history_dir / "binaries" / f"{date}.jsonl"
        install_hooks_jsonl_path = history_dir / "install_hooks" / f"{date}.jsonl"
        document = build_day_document(
            jsonl_path, binaries_jsonl_path, install_hooks_jsonl_path
        )
        (site_data_dir / f"{date}.json").write_text(
            json.dumps(document, indent=2), encoding="utf-8"
        )
        dates.append(date)
        day_documents.append((date, document))

    dates.sort(reverse=True)
    index = {
        "generated_at": _now_iso(),
        "latest": dates[0] if dates else None,
        "dates": dates,
    }
    (site_data_dir / "index.json").write_text(
        json.dumps(index, indent=2), encoding="utf-8"
    )

    trends_document = build_trends_document(day_documents)
    (site_data_dir / "trends.json").write_text(
        json.dumps(trends_document, indent=2), encoding="utf-8"
    )

    return dates


def main() -> None:
    """CLI entry point: ``build_site_data.py <history_dir> <site_data_dir>``."""
    if len(sys.argv) != 3:  # noqa: PLR2004
        print(  # noqa: T201
            f"Usage: {sys.argv[0]} <history_dir> <site_data_dir>", file=sys.stderr
        )
        sys.exit(2)

    history_dir = Path(sys.argv[1])
    site_data_dir = Path(sys.argv[2])

    if not history_dir.exists():
        print(f"No history found at {history_dir}, nothing to build.", file=sys.stderr)  # noqa: T201
        return

    dates = build_site_data(history_dir, site_data_dir)
    print(f"Wrote {len(dates)} day(s) + index.json to {site_data_dir}")  # noqa: T201


if __name__ == "__main__":
    main()
