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
        if p.is_file() and "__pycache__" not in p.parts and _is_whitelisted(p)
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


def analyze_package(
    path: Path,
    *,
    name: str | None = None,
    version: str | None = None,
    download_url: str | None = None,
) -> PackageAnalysis:
    """Analyse every whitelisted source file inside a package directory.

    Args:
        path: Absolute path to the already-extracted package directory.
        name: Package name to record on the result. Defaults to ``path.name``,
            which is only meaningful when *path* is named after the package
            (e.g. the ``analyze`` CLI flow); callers that extract into a
            fixed-name temp directory (fetch/monitor) must pass the real
            package name explicitly.
        version: Package version to record on the result, when known (the
            fetch/monitor flows resolve it from PyPI). ``None`` when the
            caller has no version concept (e.g. the ``analyze`` CLI flow).
        download_url: Direct PyPI download URL of the analysed archive, when
            known (fetch/monitor flows). ``None`` otherwise.

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

    return PackageAnalysis(
        name=name if name is not None else path.name,
        path=path,
        files=analyses,
        version=version,
        download_url=download_url,
    )
