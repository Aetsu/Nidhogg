"""Command-line interface for Nidhogg."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

from nidhogg.analysis.aggregator import aggregate, load_benign_domains
from nidhogg.analysis.walker import analyze_package
from nidhogg.core.exceptions import PackageReadError
from nidhogg.output.renderer import (
    make_console,
    render_countdown,
    render_package_header,
    render_package_result,
    render_progress,
    render_status,
)
from nidhogg.output.writer import (
    build_binaries_document,
    build_document,
    write_binary_results,
    write_results,
)

if TYPE_CHECKING:
    from rich.console import Console
    from rich.progress import Progress

    from nidhogg.core.models import PackageAnalysis
    from nidhogg.fetching.changelog import ChangelogClient, ChangelogEntry

_EXIT_ERROR = 2


def _build_parser() -> argparse.ArgumentParser:
    """Build the ``nidhogg`` argument parser with its three subcommands.

    Returns:
        The fully configured parser (``analyze``, ``fetch``, ``monitor``).
    """
    parser = argparse.ArgumentParser(
        prog="nidhogg",
        description="Static analyser of Python packages for malicious URLs.",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove cached data and saved files, then exit.",
    )
    subparsers = parser.add_subparsers(dest="command", required=False)

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
        "--check-http",
        action="store_true",
        dest="check_http",
        help=(
            "Request each http/https URL and record its response status code "
            "and page title (requires network access)."
        ),
    )
    analyze.add_argument(
        "--check-binaries",
        action="store_true",
        dest="check_binaries",
        help=(
            "Scan the package for native binaries (PE/Mach-O/ELF), hash them, "
            "and check for embedded signatures."
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
        "--history-dir",
        type=Path,
        default=None,
        metavar="PATH",
        dest="history_dir",
        help=(
            "Append each result as JSONL to <PATH>/YYYY-MM-DD.jsonl. Defaults "
            "to <project_root>/.cache/nidhogg/history."
        ),
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
    fetch.add_argument(
        "--json",
        action="store_true",
        help="Print results as JSON instead of the human-readable format.",
    )
    fetch.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="PATH",
        help="Write JSON results to PATH (implies --json).",
    )
    fetch.add_argument(
        "--history-dir",
        type=Path,
        default=None,
        metavar="PATH",
        dest="history_dir",
        help=(
            "Append the result as JSONL to <PATH>/YYYY-MM-DD.jsonl. Defaults "
            "to <project_root>/.cache/nidhogg/history."
        ),
    )
    fetch.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging to stderr.",
    )
    fetch.add_argument(
        "--check-ssl",
        action="store_true",
        dest="check_ssl",
        help=(
            "Connect to each HTTPS domain and flag Let's Encrypt certificates "
            "as suspicious (requires network access)."
        ),
    )
    fetch.add_argument(
        "--check-http",
        action="store_true",
        dest="check_http",
        help=(
            "Request each http/https URL and record its response status code "
            "and page title (requires network access)."
        ),
    )
    fetch.add_argument(
        "--check-binaries",
        action="store_true",
        dest="check_binaries",
        help=(
            "Scan the package for native binaries (PE/Mach-O/ELF), hash them, "
            "and check for embedded signatures."
        ),
    )

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
            "Defaults to <project_root>/.cache/nidhogg/monitor_state.json."
        ),
    )
    monitor.add_argument(
        "--concurrency",
        type=int,
        default=1,
        metavar="N",
        help="Maximum number of packages to download/analyse concurrently.",
    )
    monitor.add_argument(
        "--keep-download",
        type=Path,
        default=None,
        metavar="DIR",
        dest="keep_download",
        help=(
            "Keep every downloaded/extracted package under DIR instead of deleting it."
        ),
    )
    monitor.add_argument(
        "--json",
        action="store_true",
        help="Print each result as JSON instead of the human-readable format.",
    )
    monitor.add_argument(
        "--history-dir",
        type=Path,
        default=None,
        metavar="PATH",
        dest="history_dir",
        help=(
            "Append each result as JSONL to <PATH>/YYYY-MM-DD.jsonl. Defaults "
            "to <project_root>/.cache/nidhogg/history."
        ),
    )
    monitor.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging to stderr.",
    )
    monitor.add_argument(
        "--last",
        type=int,
        default=None,
        metavar="N",
        help="Process the last N newly published packages and exit (no loop).",
    )
    monitor.add_argument(
        "--once",
        action="store_true",
        help=(
            "Run a single poll using the persisted state, then exit "
            "(for scheduled jobs, e.g. GitHub Actions cron)."
        ),
    )
    monitor.add_argument(
        "--check-ssl",
        action="store_true",
        dest="check_ssl",
        help=(
            "Connect to each HTTPS domain and flag Let's Encrypt certificates "
            "as suspicious (requires network access)."
        ),
    )
    monitor.add_argument(
        "--check-http",
        action="store_true",
        dest="check_http",
        help=(
            "Request each http/https URL and record its response status code "
            "and page title (requires network access)."
        ),
    )
    monitor.add_argument(
        "--check-binaries",
        action="store_true",
        dest="check_binaries",
        help=(
            "Scan the package for native binaries (PE/Mach-O/ELF), hash them, "
            "and check for embedded signatures."
        ),
    )

    return parser


def _analyse_one(  # noqa: PLR0913
    package_path: Path,
    *,
    package_name: str | None = None,
    package_version: str | None = None,
    package_download_url: str | None = None,
    benign_domains_path: Path | None = None,
    check_ssl: bool = False,
    check_http: bool = False,
    check_binaries: bool = False,
) -> PackageAnalysis | None:
    """Run the URL-analysis pipeline for a single package directory.

    Args:
        package_path: Directory of the package to analyse.
        package_name: Package name to record on the result. Defaults to
            ``package_path.name``; pass explicitly when the directory isn't
            named after the package (e.g. fetch/monitor's fixed-name temp dir).
        package_version: Package version to record on the result, when known
            (fetch/monitor resolve it from PyPI).
        package_download_url: Direct PyPI download URL of the analysed
            archive, when known (fetch/monitor resolve it from PyPI).
        benign_domains_path: Optional path to a custom benign domain list.
        check_ssl: When ``True``, query TLS certificates for each HTTPS domain
            and populate cert_issuer for Let's Encrypt issuers.
        check_http: When ``True``, request each http/https URL, populate
            http_status/http_title, and drop http/https findings that got
            no response.
        check_binaries: When ``True``, scan the package for native binaries
            (PE/Mach-O/ELF), hash them, and check for embedded signatures.

    Returns:
        A ``PackageAnalysis``, or ``None`` on read error.
    """
    try:
        analysis = analyze_package(
            package_path,
            name=package_name,
            version=package_version,
            download_url=package_download_url,
            check_binaries=check_binaries,
        )
    except PackageReadError as exc:
        print(f"Error: {exc}", file=sys.stderr)  # noqa: T201
        return None

    if benign_domains_path is not None:
        analysis.files = aggregate(
            analysis.files,
            benign_domains=load_benign_domains(benign_domains_path),
        )
    else:
        analysis.files = aggregate(analysis.files)

    if check_ssl:
        from nidhogg.enrichment.ssl_cert import check_certificates  # noqa: PLC0415

        check_certificates(analysis.findings)

    if check_http:
        from nidhogg.enrichment.http_probe import (  # noqa: PLC0415
            check_urls,
            prune_unresponsive,
        )

        check_urls(analysis.findings)
        prune_unresponsive(analysis.files)

    return analysis


def _run_analyze(  # noqa: PLR0913
    package_path: Path,
    output: Path | None,
    *,
    as_json: bool,
    verbose: bool,
    benign_domains_path: Path | None = None,
    check_ssl: bool = False,
    check_http: bool = False,
    check_binaries: bool = False,
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
            and populate cert_issuer.
        check_http: When ``True``, request each http/https URL, populate
            http_status/http_title, and drop http/https findings that got
            no response.
        check_binaries: When ``True``, scan the package for native binaries
            (PE/Mach-O/ELF), hash them, and check for embedded signatures.
        history_dir: When provided, append the result document as JSONL under
            this directory.

    Returns:
        ``0`` on success, ``2`` on error.
    """
    if not verbose:
        logger.remove()

    result = _analyse_one(
        package_path,
        benign_domains_path=benign_domains_path,
        check_ssl=check_ssl,
        check_http=check_http,
        check_binaries=check_binaries,
    )
    if result is None:
        return _EXIT_ERROR

    analysis = result

    if history_dir is not None:
        from nidhogg.output.history import (  # noqa: PLC0415
            append_binary_finding,
            append_finding,
        )

        append_finding(history_dir, build_document(analysis))
        append_binary_finding(history_dir, build_binaries_document(analysis))

    if output is not None:
        write_results(analysis, output)
        write_binary_results(analysis, output)
    elif as_json:
        print(json.dumps(build_document(analysis), indent=2))  # noqa: T201
    else:
        console = make_console()
        console.print(render_package_result(analysis))

    return 0


def _run_batch(  # noqa: PLR0913
    packages_dir: Path,
    output: Path | None,
    *,
    as_json: bool,
    verbose: bool,
    benign_domains_path: Path | None = None,
    check_ssl: bool = False,
    check_http: bool = False,
    check_binaries: bool = False,
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
            and populate cert_issuer.
        check_http: When ``True``, request each http/https URL, populate
            http_status/http_title, and drop http/https findings that got
            no response.
        check_binaries: When ``True``, scan the package for native binaries
            (PE/Mach-O/ELF), hash them, and check for embedded signatures.
        history_dir: When provided, append each package's result document as
            JSONL under this directory.

    Returns:
        ``0`` on success, ``2`` if any package could not be read.
    """
    if not verbose:
        logger.remove()

    console = make_console()

    subdirs = sorted(p for p in packages_dir.iterdir() if p.is_dir())
    if not subdirs:
        print(f"No package directories found in {packages_dir}", file=sys.stderr)  # noqa: T201
        return _EXIT_ERROR

    exit_code = 0
    documents: list[dict[str, object]] = []

    for pkg_dir in subdirs:
        result = _analyse_one(
            pkg_dir,
            benign_domains_path=benign_domains_path,
            check_ssl=check_ssl,
            check_http=check_http,
            check_binaries=check_binaries,
        )
        if result is None:
            exit_code = _EXIT_ERROR
            continue

        analysis = result

        if history_dir is not None:
            from nidhogg.output.history import (  # noqa: PLC0415
                append_binary_finding,
                append_finding,
            )

            append_finding(history_dir, build_document(analysis))
            append_binary_finding(history_dir, build_binaries_document(analysis))

        if output is not None or as_json:
            documents.append(build_document(analysis))
        else:
            if analysis.findings:
                console.print()
                console.print(render_package_header(pkg_dir.name))
            console.print(render_package_result(analysis, display_name=pkg_dir.name))

    if output is not None:
        output.write_text(json.dumps(documents, indent=2), encoding="utf-8")
    elif as_json:
        print(json.dumps(documents, indent=2))  # noqa: T201

    return exit_code


def _run_fetch(  # noqa: PLR0913
    name: str,
    version: str | None,
    output: Path | None,
    *,
    as_json: bool,
    verbose: bool,
    keep_download: str | None,
    history_dir: Path | None,
    check_ssl: bool = False,
    check_http: bool = False,
    check_binaries: bool = False,
) -> int:
    """Download *name* from PyPI, analyse it, and return an exit code.

    Args:
        name: PyPI package name to download.
        version: Specific version to download, or ``None`` for the latest.
        output: Write JSON to this path; ``None`` prints to stdout.
        as_json: Print JSON to stdout instead of the human-readable format.
        verbose: Keep loguru logging enabled when True.
        keep_download: ``None`` to delete after analysis; ``""`` to keep in
            place; a non-empty string is a directory to move the extracted
            package into.
        history_dir: When provided, append the result document as JSONL
            under this directory.
        check_ssl: When ``True``, query TLS certificates for each HTTPS domain
            and populate cert_issuer.
        check_http: When ``True``, request each http/https URL, populate
            http_status/http_title, and drop http/https findings that got
            no response.
        check_binaries: When ``True``, scan the package for native binaries
            (PE/Mach-O/ELF), hash them, and check for embedded signatures.

    Returns:
        ``0`` on success, ``2`` on error.
    """
    if not verbose:
        logger.remove()

    from nidhogg.fetching.pypi_fetch import fetched_package  # noqa: PLC0415

    keep = keep_download is not None
    keep_dir = Path(keep_download) if keep_download else None

    try:
        with fetched_package(name, version, keep=keep, keep_dir=keep_dir) as (
            path,
            resolved_version,
            download_url,
        ):
            result = _analyse_one(
                path,
                package_name=name,
                package_version=resolved_version,
                package_download_url=download_url,
                check_ssl=check_ssl,
                check_http=check_http,
                check_binaries=check_binaries,
            )
    except PackageReadError as exc:
        print(f"Error: {exc}", file=sys.stderr)  # noqa: T201
        return _EXIT_ERROR

    if result is None:
        return _EXIT_ERROR

    analysis = result

    if history_dir is not None:
        from nidhogg.output.history import (  # noqa: PLC0415
            append_binary_finding,
            append_finding,
        )

        append_finding(history_dir, build_document(analysis))
        append_binary_finding(history_dir, build_binaries_document(analysis))

    if output is not None:
        write_results(analysis, output)
        write_binary_results(analysis, output)
    elif as_json:
        print(json.dumps(build_document(analysis), indent=2))  # noqa: T201
    else:
        console = make_console()
        console.print(render_package_result(analysis))

    return 0


def _analyse_new_package(
    name: str,
    *,
    keep_download: Path | None,
    check_ssl: bool = False,
    check_http: bool = False,
    check_binaries: bool = False,
) -> PackageAnalysis | None:
    """Download, analyse, and clean up a single monitor-discovered package.

    Args:
        name: PyPI package name to download and analyse.
        keep_download: When provided, keep the extracted package under a
            per-package subdirectory of this directory.
        check_ssl: When ``True``, query TLS certificates for each HTTPS domain
            and populate cert_issuer.
        check_http: When ``True``, request each http/https URL, populate
            http_status/http_title, and drop http/https findings that got
            no response.
        check_binaries: When ``True``, scan the package for native binaries
            (PE/Mach-O/ELF), hash them, and check for embedded signatures.

    Returns:
        A ``PackageAnalysis``, or ``None`` on read error.
    """
    from nidhogg.fetching.pypi_fetch import fetched_package  # noqa: PLC0415

    keep = keep_download is not None
    keep_dir = keep_download / name if keep_download is not None else None
    with fetched_package(name, keep=keep, keep_dir=keep_dir) as (
        path,
        resolved_version,
        download_url,
    ):
        return _analyse_one(
            path,
            package_name=name,
            package_version=resolved_version,
            package_download_url=download_url,
            check_ssl=check_ssl,
            check_http=check_http,
            check_binaries=check_binaries,
        )


def _process_entries_plain(  # noqa: PLR0913
    entries: list[ChangelogEntry],
    *,
    keep_download: Path | None,
    concurrency: int,
    history_dir: Path | None,
    as_json: bool,
    check_ssl: bool = False,
    check_http: bool = False,
    check_binaries: bool = False,
) -> None:
    """Analyse *entries* concurrently and print each result as it completes.

    This is the non-interactive code path used whenever stdout is not a
    terminal (redirected output, logs, CI) — no rich rendering involved.

    Args:
        entries: Changelog entries to analyse.
        keep_download: Forwarded to :func:`_analyse_new_package`.
        concurrency: Maximum concurrent downloads/analyses.
        history_dir: When provided, append each result to JSONL history.
        as_json: Print each result as JSON instead of the human-readable format.
        check_ssl: When ``True``, query TLS certificates for each HTTPS domain
            and populate cert_issuer.
        check_http: When ``True``, request each http/https URL, populate
            http_status/http_title, and drop http/https findings that got
            no response.
        check_binaries: When ``True``, scan the package for native binaries
            (PE/Mach-O/ELF), hash them, and check for embedded signatures.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed  # noqa: PLC0415

    console = make_console()

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {
            pool.submit(
                _analyse_new_package,
                entry.name,
                keep_download=keep_download,
                check_ssl=check_ssl,
                check_http=check_http,
                check_binaries=check_binaries,
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
            analysis = result
            if history_dir is not None:
                from nidhogg.output.history import (  # noqa: PLC0415
                    append_binary_finding,
                    append_finding,
                )

                append_finding(history_dir, build_document(analysis))
                append_binary_finding(history_dir, build_binaries_document(analysis))
            if as_json:
                print(json.dumps(build_document(analysis), indent=2))  # noqa: T201
            else:
                if analysis.findings:
                    console.print()
                    console.print(render_package_header(entry.name))
                console.print(render_package_result(analysis, display_name=entry.name))


def _run_monitor_iteration_plain(  # noqa: PLR0913
    client: ChangelogClient,
    last_serial: int,
    *,
    keep_download: Path | None,
    concurrency: int,
    history_dir: Path | None,
    as_json: bool,
    check_ssl: bool = False,
    check_http: bool = False,
    check_binaries: bool = False,
) -> int:
    """Poll the changelog once and analyse any new packages, plainly.

    Args:
        client: Changelog client to poll.
        last_serial: The last processed changelog serial.
        keep_download: Forwarded to :func:`_analyse_new_package`.
        concurrency: Maximum concurrent downloads/analyses.
        history_dir: When provided, append each result to JSONL history.
        as_json: Print each result as JSON instead of the human-readable format.
        check_ssl: When ``True``, query TLS certificates for each HTTPS domain
            and populate cert_issuer.
        check_http: When ``True``, request each http/https URL, populate
            http_status/http_title, and drop http/https findings that got
            no response.
        check_binaries: When ``True``, scan the package for native binaries
            (PE/Mach-O/ELF), hash them, and check for embedded signatures.

    Returns:
        The changelog serial observed at the start of this call — the new
        high-water mark once persisted by the caller.
    """
    current_serial = client.current_serial()
    entries = [e for e in client.entries_since(last_serial) if e.is_new_project]
    logger.info("Monitor: {} new package(s) since serial {}", len(entries), last_serial)

    if entries:
        _process_entries_plain(
            entries,
            keep_download=keep_download,
            concurrency=concurrency,
            history_dir=history_dir,
            as_json=as_json,
            check_ssl=check_ssl,
            check_http=check_http,
            check_binaries=check_binaries,
        )

    return current_serial


def _analyse_with_progress(  # noqa: PLR0913
    entry: ChangelogEntry,
    progress: Progress,
    keep_download: Path | None,
    check_ssl: bool = False,  # noqa: FBT001, FBT002
    check_http: bool = False,  # noqa: FBT001, FBT002
    check_binaries: bool = False,  # noqa: FBT001, FBT002
) -> PackageAnalysis | None:
    """Analyse *entry*, showing a spinner row only while this call is active.

    The spinner task is added when the call actually starts (i.e. once a
    worker thread picks it up) and removed when it finishes, so the live
    display only ever shows up to ``concurrency`` rows — the packages
    genuinely being analysed right now, not the whole queue.

    Args:
        entry: Changelog entry to analyse.
        progress: Shared progress display to add/remove this row on.
        keep_download: Forwarded to :func:`_analyse_new_package`.
        check_ssl: When ``True``, query TLS certificates for each HTTPS domain
            and populate cert_issuer.
        check_http: When ``True``, request each http/https URL, populate
            http_status/http_title, and drop http/https findings that got
            no response.
        check_binaries: When ``True``, scan the package for native binaries
            (PE/Mach-O/ELF), hash them, and check for embedded signatures.

    Returns:
        A ``PackageAnalysis``, or ``None`` on read error.
    """
    task_id = progress.add_task(f"  {entry.name}", total=None)
    try:
        return _analyse_new_package(
            entry.name,
            keep_download=keep_download,
            check_ssl=check_ssl,
            check_http=check_http,
            check_binaries=check_binaries,
        )
    finally:
        progress.remove_task(task_id)


def _process_entries_rich(  # noqa: PLR0913
    entries: list[ChangelogEntry],
    *,
    keep_download: Path | None,
    concurrency: int,
    history_dir: Path | None,
    as_json: bool,
    console: Console,
    check_ssl: bool = False,
    check_http: bool = False,
    check_binaries: bool = False,
) -> None:
    """Analyse *entries* concurrently with a live rich progress display.

    Shows an overall "completed/total" bar plus one spinner row per package
    currently being analysed. Each result is printed through the progress's
    own console so the live display isn't corrupted.

    Args:
        entries: Changelog entries to analyse.
        keep_download: Forwarded to :func:`_analyse_new_package`.
        concurrency: Maximum concurrent downloads/analyses.
        history_dir: When provided, append each result to JSONL history.
        as_json: Print each result as JSON instead of the human-readable format.
        console: Rich console shared with the rest of the monitor loop.
        check_ssl: When ``True``, query TLS certificates for each HTTPS domain
            and populate cert_issuer.
        check_http: When ``True``, request each http/https URL, populate
            http_status/http_title, and drop http/https findings that got
            no response.
        check_binaries: When ``True``, scan the package for native binaries
            (PE/Mach-O/ELF), hash them, and check for embedded signatures.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed  # noqa: PLC0415

    with render_progress(console=console) as progress:
        overall_task = progress.add_task("Analizando paquetes", total=len(entries))

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {
                pool.submit(
                    _analyse_with_progress,
                    entry,
                    progress,
                    keep_download,
                    check_ssl,
                    check_http,
                    check_binaries,
                ): entry
                for entry in entries
            }
            for future in as_completed(futures):
                entry = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001
                    logger.error("Failed to analyse {}: {}", entry.name, exc)
                    progress.advance(overall_task)
                    continue
                progress.advance(overall_task)
                if result is None:
                    continue
                analysis = result
                if history_dir is not None:
                    from nidhogg.output.history import (  # noqa: PLC0415
                        append_binary_finding,
                        append_finding,
                    )

                    append_finding(history_dir, build_document(analysis))
                    append_binary_finding(
                        history_dir, build_binaries_document(analysis)
                    )
                if as_json:
                    progress.console.print(
                        json.dumps(build_document(analysis), indent=2),
                        markup=False,
                    )
                else:
                    if analysis.findings:
                        progress.console.print()
                        progress.console.print(
                            render_package_header(entry.name),
                            markup=False,
                        )
                    progress.console.print(
                        render_package_result(analysis, display_name=entry.name),
                        markup=False,
                    )


def _run_monitor_iteration_rich(  # noqa: PLR0913
    client: ChangelogClient,
    last_serial: int,
    console: Console,
    *,
    keep_download: Path | None,
    concurrency: int,
    history_dir: Path | None,
    as_json: bool,
    check_ssl: bool = False,
    check_http: bool = False,
    check_binaries: bool = False,
) -> int:
    """Poll the changelog once and analyse any new packages, with rich output.

    Args:
        client: Changelog client to poll.
        last_serial: The last processed changelog serial.
        console: Rich console shared with the rest of the monitor loop.
        keep_download: Forwarded to :func:`_analyse_new_package`.
        concurrency: Maximum concurrent downloads/analyses.
        history_dir: When provided, append each result to JSONL history.
        as_json: Print each result as JSON instead of the human-readable format.
        check_ssl: When ``True``, query TLS certificates for each HTTPS domain
            and populate cert_issuer.
        check_http: When ``True``, request each http/https URL, populate
            http_status/http_title, and drop http/https findings that got
            no response.
        check_binaries: When ``True``, scan the package for native binaries
            (PE/Mach-O/ELF), hash them, and check for embedded signatures.

    Returns:
        The changelog serial observed at the start of this call — the new
        high-water mark once persisted by the caller.
    """
    with render_status("Comprobando PyPI...", console=console):
        current_serial = client.current_serial()
        entries = [e for e in client.entries_since(last_serial) if e.is_new_project]
    logger.info("Monitor: {} new package(s) since serial {}", len(entries), last_serial)

    if entries:
        _process_entries_rich(
            entries,
            keep_download=keep_download,
            concurrency=concurrency,
            history_dir=history_dir,
            as_json=as_json,
            console=console,
            check_ssl=check_ssl,
            check_http=check_http,
            check_binaries=check_binaries,
        )

    return current_serial


def _wait_before_next_poll_rich(interval: int, console: Console) -> None:
    """Sleep for *interval* seconds showing a live countdown spinner.

    Delegates to :func:`nidhogg.output.renderer.render_countdown`, which
    preserves the invariant that ``time.sleep`` is called at least once even
    when ``interval <= 0``.

    Args:
        interval: Seconds to wait before the next changelog poll.
        console: Rich console shared with the rest of the monitor loop.
    """
    render_countdown(interval, console=console)


def _run_monitor_once(  # noqa: PLR0913
    client: ChangelogClient,
    last_serial: int,
    resolved_index_file: Path,
    *,
    keep_download: Path | None,
    concurrency: int,
    history_dir: Path | None,
    as_json: bool,
    check_ssl: bool = False,
    check_http: bool = False,
    check_binaries: bool = False,
) -> int:
    """Run a single monitor poll from *last_serial*, persist state, and exit.

    Args:
        client: Changelog client to poll.
        last_serial: The last processed changelog serial (from persisted state).
        resolved_index_file: Where to persist the new high-water-mark serial.
        keep_download: Forwarded to :func:`_analyse_new_package`.
        concurrency: Maximum concurrent downloads/analyses.
        history_dir: When provided, append each result to JSONL history.
        as_json: Print each result as JSON instead of the human-readable format.
        check_ssl: When ``True``, query TLS certificates for each HTTPS domain
            and populate cert_issuer.
        check_http: When ``True``, request each http/https URL, populate
            http_status/http_title, and drop http/https findings that got
            no response.
        check_binaries: When ``True``, scan the package for native binaries
            (PE/Mach-O/ELF), hash them, and check for embedded signatures.

    Returns:
        ``0`` once the single poll completes and state is persisted.
    """
    from nidhogg.fetching.monitor_state import MonitorState, save_state  # noqa: PLC0415

    if sys.stdout.isatty():
        console = make_console()
        new_serial = _run_monitor_iteration_rich(
            client,
            last_serial,
            console,
            keep_download=keep_download,
            concurrency=concurrency,
            history_dir=history_dir,
            as_json=as_json,
            check_ssl=check_ssl,
            check_http=check_http,
            check_binaries=check_binaries,
        )
    else:
        new_serial = _run_monitor_iteration_plain(
            client,
            last_serial,
            keep_download=keep_download,
            concurrency=concurrency,
            history_dir=history_dir,
            as_json=as_json,
            check_ssl=check_ssl,
            check_http=check_http,
            check_binaries=check_binaries,
        )
    save_state(resolved_index_file, MonitorState(last_serial=new_serial))
    return 0


_DEFAULT_INITIAL_BACKFILL = 40


def _estimate_changelog_start(client: ChangelogClient, count: int) -> int:
    """Estimate a serial that comfortably precedes *count* new-project entries.

    PyPI changelog serials advance for every release/upload event, not just
    project creations, so this backs off ``count * 100`` from the current
    serial as a rough heuristic; callers filter the result for actual
    ``is_new_project`` entries.

    Args:
        client: Changelog client used to read the current serial.
        count: Number of new-project entries the estimate should cover.

    Returns:
        A serial to pass to :meth:`ChangelogClient.entries_since`.
    """
    return max(0, client.current_serial() - count * 100)


def _initial_backfill_serial(
    client: ChangelogClient, backfill: int = _DEFAULT_INITIAL_BACKFILL
) -> int:
    """Pick a starting serial for a monitor run with no persisted state.

    Without this, the very first run would start from "now" and find
    nothing new until a package happens to be published. Instead, back off
    far enough to include the last *backfill* newly created projects.

    Args:
        client: Changelog client to poll.
        backfill: Number of most-recent new packages to include.

    Returns:
        A serial such that ``entries_since`` from it yields at least
        *backfill* new-project entries (or all available ones, if fewer
        exist).
    """
    estimated_start = _estimate_changelog_start(client, backfill)
    new_packages = [
        e for e in client.entries_since(estimated_start) if e.is_new_project
    ]
    if len(new_packages) <= backfill:
        return estimated_start
    return new_packages[-backfill - 1].serial


def _run_monitor_last_n(  # noqa: PLR0913
    client: ChangelogClient,
    last_n: int,
    resolved_index_file: Path,
    *,
    keep_download: Path | None,
    concurrency: int,
    history_dir: Path | None,
    as_json: bool,
    check_ssl: bool = False,
    check_http: bool = False,
    check_binaries: bool = False,
) -> int:
    """Process the last *last_n* newly published packages and exit.

    Ignores any previously persisted serial: estimates a changelog start
    point from the current serial and walks forward from there.

    Args:
        client: Changelog client to poll.
        last_n: Number of most-recent new packages to process.
        resolved_index_file: Where to persist the observed high-water-mark
            serial once processing completes.
        keep_download: Forwarded to :func:`_analyse_new_package`.
        concurrency: Maximum concurrent downloads/analyses.
        history_dir: When provided, append each result to JSONL history.
        as_json: Print each result as JSON instead of the human-readable format.
        check_ssl: When ``True``, query TLS certificates for each HTTPS domain
            and populate cert_issuer.
        check_http: When ``True``, request each http/https URL, populate
            http_status/http_title, and drop http/https findings that got
            no response.
        check_binaries: When ``True``, scan the package for native binaries
            (PE/Mach-O/ELF), hash them, and check for embedded signatures.

    Returns:
        ``0`` once processing completes (even if no packages were found).
    """
    from nidhogg.fetching.monitor_state import MonitorState, save_state  # noqa: PLC0415

    estimated_start = _estimate_changelog_start(client, last_n)
    all_entries = client.entries_since(estimated_start)
    new_packages = [e for e in all_entries if e.is_new_project]
    entries_to_process = new_packages[-last_n:]

    if not entries_to_process:
        print("No newly published packages found.")  # noqa: T201
        return 0

    if sys.stdout.isatty():
        console = make_console()
        _process_entries_rich(
            entries_to_process,
            keep_download=keep_download,
            concurrency=concurrency,
            history_dir=history_dir,
            as_json=as_json,
            console=console,
            check_ssl=check_ssl,
            check_http=check_http,
            check_binaries=check_binaries,
        )
    else:
        _process_entries_plain(
            entries_to_process,
            keep_download=keep_download,
            concurrency=concurrency,
            history_dir=history_dir,
            as_json=as_json,
            check_ssl=check_ssl,
            check_http=check_http,
            check_binaries=check_binaries,
        )

    save_state(
        resolved_index_file,
        MonitorState(last_serial=entries_to_process[-1].serial),
    )
    return 0


def _run_monitor(  # noqa: PLR0913
    *,
    interval: int,
    index_file: Path | None,
    concurrency: int,
    keep_download: Path | None,
    as_json: bool,
    history_dir: Path | None,
    verbose: bool,
    last_n: int | None = None,
    once: bool = False,
    check_ssl: bool = False,
    check_http: bool = False,
    check_binaries: bool = False,
) -> int:
    """Poll the PyPI changelog for new packages and analyse each one.

    Runs until interrupted with Ctrl+C. Each iteration fetches every
    changelog entry with ``action == "create"`` since the last processed
    serial, downloads and analyses each concurrently, prints results as they
    complete, and persists the new high-water-mark serial. When stdout is a
    terminal, a live rich display shows whether the monitor is waiting for
    the next poll or actively analysing packages; otherwise it falls back to
    plain logging, unchanged from before. With no persisted state (first
    run, or after clearing the index file), bootstraps by backfilling the
    last :data:`_DEFAULT_INITIAL_BACKFILL` newly published packages instead
    of starting from "now".

    Args:
        interval: Seconds to sleep between iterations.
        index_file: Where to persist the last processed serial. Defaults to
            ``<project_root>/.cache/nidhogg/monitor_state.json``.
        concurrency: Maximum concurrent downloads/analyses.
        keep_download: When provided, keep each downloaded package under a
            per-package subdirectory of this directory.
        as_json: Print each result as a JSON document instead of the
            human-readable format.
        history_dir: When provided, append each result document as JSONL
            under this directory.
        verbose: Keep loguru logging enabled when True.
        last_n: When provided, process only the last N newly published
            packages and exit (no loop).
        once: When ``True``, run a single poll starting from the persisted
            state, save the new state, and exit — no loop, no sleep. Takes
            precedence over ``interval`` and is meant for scheduled jobs
            (e.g. a GitHub Actions cron run) that start and finish rather
            than running forever.
        check_ssl: When ``True``, query TLS certificates for each HTTPS domain
            and populate cert_issuer.
        check_http: When ``True``, request each http/https URL, populate
            http_status/http_title, and drop http/https findings that got
            no response.
        check_binaries: When ``True``, scan the package for native binaries
            (PE/Mach-O/ELF), hash them, and check for embedded signatures.

    Returns:
        ``0`` when the monitor completes (``--once``/``--last``) or is
        stopped cleanly via Ctrl+C.
    """
    if not verbose:
        logger.remove()

    import time  # noqa: PLC0415

    from nidhogg.fetching.changelog import ChangelogClient  # noqa: PLC0415
    from nidhogg.fetching.monitor_state import (  # noqa: PLC0415
        MonitorState,
        default_index_file,
        load_state,
        save_state,
    )

    resolved_index_file = index_file or default_index_file()
    client = ChangelogClient()

    if last_n is not None:
        return _run_monitor_last_n(
            client,
            last_n,
            resolved_index_file,
            keep_download=keep_download,
            concurrency=concurrency,
            history_dir=history_dir,
            as_json=as_json,
            check_ssl=check_ssl,
            check_http=check_http,
            check_binaries=check_binaries,
        )

    state = load_state(resolved_index_file)
    last_serial = (
        state.last_serial if state is not None else _initial_backfill_serial(client)
    )

    if once:
        return _run_monitor_once(
            client,
            last_serial,
            resolved_index_file,
            keep_download=keep_download,
            concurrency=concurrency,
            history_dir=history_dir,
            as_json=as_json,
            check_ssl=check_ssl,
            check_http=check_http,
            check_binaries=check_binaries,
        )

    use_rich = sys.stdout.isatty()

    try:
        if use_rich:
            console = make_console()
            while True:
                last_serial = _run_monitor_iteration_rich(
                    client,
                    last_serial,
                    console,
                    keep_download=keep_download,
                    concurrency=concurrency,
                    history_dir=history_dir,
                    as_json=as_json,
                    check_ssl=check_ssl,
                    check_http=check_http,
                    check_binaries=check_binaries,
                )
                save_state(resolved_index_file, MonitorState(last_serial=last_serial))
                _wait_before_next_poll_rich(interval, console)
        else:
            while True:
                last_serial = _run_monitor_iteration_plain(
                    client,
                    last_serial,
                    keep_download=keep_download,
                    concurrency=concurrency,
                    history_dir=history_dir,
                    as_json=as_json,
                    check_ssl=check_ssl,
                    check_http=check_http,
                    check_binaries=check_binaries,
                )
                save_state(resolved_index_file, MonitorState(last_serial=last_serial))
                time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("Monitor stopped at serial {}", last_serial)

    return 0


def _run_clean(history_dir: Path | None = None) -> int:
    """Remove cached data and saved files.

    Args:
        history_dir: When provided, also remove this directory.

    Returns:
        ``0`` on success.
    """
    from nidhogg.fetching.monitor_state import default_index_file  # noqa: PLC0415

    cache_dir = default_index_file().parent
    removed_any = False

    if cache_dir.exists():
        shutil.rmtree(cache_dir)
        print(f"Removed {cache_dir}")  # noqa: T201
        removed_any = True

    if history_dir is not None and history_dir.exists():
        shutil.rmtree(history_dir)
        print(f"Removed {history_dir}")  # noqa: T201
        removed_any = True

    if not removed_any:
        print("Nothing to clean.")  # noqa: T201

    return 0


def main() -> None:
    """Entry point for the ``nidhogg`` CLI."""
    parser = _build_parser()
    args = parser.parse_args()

    if args.clean:
        history_dir = getattr(args, "history_dir", None)
        sys.exit(_run_clean(history_dir))

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    from nidhogg.output.history import default_history_dir  # noqa: PLC0415

    resolved_history_dir: Path = args.history_dir or default_history_dir()

    if args.command == "analyze":
        package_path: Path = args.package_path
        if args.batch:
            sys.exit(
                _run_batch(
                    package_path,
                    args.output,
                    as_json=args.json,
                    verbose=args.verbose,
                    benign_domains_path=args.benign_domains,
                    check_ssl=args.check_ssl,
                    check_http=args.check_http,
                    check_binaries=args.check_binaries,
                    history_dir=resolved_history_dir,
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
                    check_http=args.check_http,
                    check_binaries=args.check_binaries,
                    history_dir=resolved_history_dir,
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
                keep_download=args.keep_download,
                history_dir=resolved_history_dir,
                check_ssl=args.check_ssl,
                check_http=args.check_http,
                check_binaries=args.check_binaries,
            )
        )
    else:
        sys.exit(
            _run_monitor(
                interval=args.interval,
                index_file=args.index_file,
                concurrency=args.concurrency,
                keep_download=args.keep_download,
                as_json=args.json,
                history_dir=resolved_history_dir,
                verbose=args.verbose,
                last_n=args.last,
                once=args.once,
                check_ssl=args.check_ssl,
                check_http=args.check_http,
                check_binaries=args.check_binaries,
            )
        )


if __name__ == "__main__":
    main()
