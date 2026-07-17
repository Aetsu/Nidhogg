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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_METHOD_TAGS = {"via_base64", "via_concat", "via_fstring", "via_scope", "raw_ip"}
_THREAT_TAGS = {
    "shortener",
    "tunneling",
    "exfiltration",
    "ip_recon",
    "malware_hosting",
    "suspicious_tld",
}


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


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Parse each non-blank line of *path* as a JSON document."""
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def build_day_document(jsonl_path: Path) -> dict[str, Any]:
    """Build the site's per-day document from one ``history/*.jsonl`` file.

    Args:
        jsonl_path: Path to a single day's history file.

    Returns:
        A dict with ``generated_at``, ``stats``, and ``packages`` — the
        same shape the site's ``app.js`` already consumes, scoped to this
        one day.
    """
    packages = [_to_site_package(doc) for doc in _read_jsonl(jsonl_path)]
    malicious = sum(
        1 for pkg in packages if any(f["domain_threat"] for f in pkg["findings"])
    )
    return {
        "generated_at": _now_iso(),
        "stats": {
            "total_packages": len(packages),
            "malicious": malicious,
            "clean": len(packages) - malicious,
        },
        "packages": packages,
    }


def build_site_data(history_dir: Path, site_data_dir: Path) -> list[str]:
    """Rebuild every per-day JSON plus the index under *site_data_dir*.

    Reprocesses every ``history/*.jsonl`` file on each call — cheap given
    per-day file sizes, and avoids keeping incremental state to maintain.

    Args:
        history_dir: Directory containing ``history/*.jsonl`` files.
        site_data_dir: Directory to write ``YYYY-MM-DD.json`` + ``index.json``
            into. Created if missing.

    Returns:
        The dates written, sorted descending (most recent first).
    """
    site_data_dir.mkdir(parents=True, exist_ok=True)

    dates: list[str] = []
    for jsonl_path in sorted(history_dir.glob("*.jsonl")):
        date = jsonl_path.stem
        document = build_day_document(jsonl_path)
        (site_data_dir / f"{date}.json").write_text(
            json.dumps(document, indent=2), encoding="utf-8"
        )
        dates.append(date)

    dates.sort(reverse=True)
    index = {
        "generated_at": _now_iso(),
        "latest": dates[0] if dates else None,
        "dates": dates,
    }
    (site_data_dir / "index.json").write_text(
        json.dumps(index, indent=2), encoding="utf-8"
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
