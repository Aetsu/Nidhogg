"""Output writer: serialize analysis results to disk as JSON."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from nidhogg.core.models import FileAnalysis, PackageAnalysis, UrlFinding


def _serialise_finding(finding: UrlFinding) -> dict[str, object]:
    """Convert a single finding to a JSON-serialisable dict.

    Args:
        finding: The finding to serialise.

    Returns:
        A plain dict suitable for ``json.dumps``.
    """
    return {
        "url": finding.value,
        "line": finding.lineno,
        "layer": finding.layer.value,
        "tags": sorted(t.value for t in finding.tags),
        "cert_issuer": finding.cert_issuer,
        "http_status": finding.http_status,
        "http_title": finding.http_title,
    }


def _serialise_file(
    file_analysis: FileAnalysis, package_path: Path
) -> dict[str, object]:
    """Convert one :class:`FileAnalysis` to a JSON-serialisable dict.

    The file path is expressed relative to *package_path* for portability.

    Args:
        file_analysis: The per-file analysis to serialise.
        package_path: Root of the analysed package (used to relativise paths).

    Returns:
        A plain dict suitable for ``json.dumps``.
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
        "package": {
            "name": analysis.name,
            "path": str(analysis.path),
            "version": analysis.version,
            "download_url": analysis.download_url,
        },
        "summary": {
            "total_findings": len(analysis.findings),
            "total_files": len(analysis.files),
        },
        "files": [_serialise_file(fa, analysis.path) for fa in analysis.files],
    }


def write_results(analysis: PackageAnalysis, destination: Path) -> None:
    """Write analysis results to *destination* as a JSON file.

    The document contains:

    * **package** — name and path of the analysed package.
    * **summary** — total finding and file counts.
    * **files** — per-file entries, each with its relative path, context
      tags, and the URL findings collected from that file (with tags,
      line, detection layer, and certificate metadata).

    Args:
        analysis: Completed package analysis.
        destination: Path where the JSON file will be written.  The parent
            directory must already exist.
    """
    destination.write_text(
        json.dumps(build_document(analysis), indent=2), encoding="utf-8"
    )
