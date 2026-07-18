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
    PUNYCODE = "punycode"


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
        http_status: Final HTTP status code after redirects, set by the
            HTTP-probe enrichment step. ``None`` when not checked or no
            response.
        http_title: Cleaned page ``<title>`` (whitespace-collapsed, ≤200
            chars), set by the HTTP-probe enrichment step. ``None`` when not
            checked, no response, or no title.
    """

    value: str
    filepath: Path
    lineno: int
    layer: AnalysisLayer
    tags: set[UrlTag] = field(default_factory=set)
    cert_issuer: str | None = None
    http_status: int | None = None
    http_title: str | None = None


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
        version: Package version, when known (PyPI fetch/monitor flows).
            ``None`` for the batch ``analyze`` flow, which has no version
            concept — it only sees an already-extracted directory.
        download_url: Direct PyPI download URL of the analysed archive, when
            known (PyPI fetch/monitor flows). Used to link to the exact
            distribution on inspector.pypi.io. ``None`` for the batch
            ``analyze`` flow.
    """

    name: str
    path: Path
    files: list[FileAnalysis] = field(default_factory=list)
    version: str | None = None
    download_url: str | None = None

    @property
    def findings(self) -> list[UrlFinding]:
        """Flatten the findings of every analysed file.

        Returns:
            Every :class:`UrlFinding` across all files, in file order.
        """
        return [finding for fa in self.files for finding in fa.findings]
