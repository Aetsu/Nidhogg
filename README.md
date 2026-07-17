# Nidhogg

Static analyzer for Python packages focused on detecting suspicious URLs.
Takes already-extracted PyPI package folders and extracts every candidate URL (literal, obfuscated, or dynamically built) along with qualitative detection data.

## Requirements

- Python 3.14+
- [uv](https://docs.astral.sh/uv/)

## Installation

```bash
uv sync
```

## Usage

```bash
# Analyze a package
uv run nidhogg.py analyze <package_path>

# With JSON output to a file
uv run nidhogg.py analyze <package_path> --output results.json

# Custom benign-domains list
uv run nidhogg.py analyze <package_path> --benign-domains my_domains.txt

# TLS enrichment (requires network access)
uv run nidhogg.py analyze <package_path> --check-ssl

# Batch analysis
uv run nidhogg.py analyze <packages_directory> --batch --output results.json

# Verbose logging
uv run nidhogg.py analyze <package_path> --verbose

# Download and analyze a single package from PyPI
uv run nidhogg.py fetch requests

# Specific version, keep the download
uv run nidhogg.py fetch requests --version 2.31.0 --keep-download ./downloads

# Watch PyPI for new releases and analyze each one
uv run nidhogg.py monitor --interval 60 --concurrency 8

# Process the last 10 newly published packages and exit
uv run nidhogg.py monitor --last 10

# Single iteration from the persisted state, then exit (cron/CI)
uv run nidhogg.py monitor --once --history-dir ./history

# Clean cache and saved files
uv run nidhogg.py --clean

# Clean cache + history directory
uv run nidhogg.py --clean --history-dir ./history
```

### Available options — `analyze`

| Option | Description |
|--------|-------------|
| `--json` | Print JSON to stdout |
| `--output PATH` | Write JSON to a file |
| `--benign-domains PATH` | Custom benign-domains list |
| `--check-ssl` | Verify TLS certificates (requires network access) |
| `--check-http` | Probe every http/https URL and record its status and page title (requires network access) |
| `--verbose` | Enable debug logging |
| `--batch` | Treat the input as a directory of packages |
| `--history-dir PATH` | Append each result as JSONL to `<PATH>/YYYY-MM-DD.jsonl` (defaults to `.cache/nidhogg/history` under the project directory) |

### `fetch` — on-demand single download

Downloads a specific package from PyPI (`nidhogg/fetching/pypi_fetch.py`),
extracts it to a temporary directory, and runs the same analysis pipeline.
Its own discovery mechanism, independent of the batch flow's external
downloader.

| Option | Description |
|--------|-------------|
| `name` | PyPI package name (positional) |
| `--version VERSION` | Specific version; defaults to the latest release |
| `--keep-download [DIR]` | Keep the download/extraction instead of deleting it |
| `--check-ssl`, `--check-http` | Opt-in network enrichment (same as `analyze`) |
| `--json`, `--output PATH`, `--history-dir PATH`, `--verbose` | Same as `analyze` |

### `monitor` — watching for new PyPI releases

Polls PyPI's XML-RPC changelog (`nidhogg/fetching/changelog.py`) in a loop,
downloads and analyzes every newly published package, and persists the
last processed serial (`nidhogg/fetching/monitor_state.py`) so it can
resume without reprocessing releases it already saw. With no persisted
state (first run, or after `--clean`), it bootstraps by backfilling the
last 40 newly published packages instead of starting from "now".

| Option | Description |
|--------|-------------|
| `--interval SECONDS` | Seconds between polling iterations (default 300) |
| `--index-file PATH` | Where to persist the last processed serial (default `.cache/nidhogg/monitor_state.json` under the project directory) |
| `--concurrency N` | Max number of packages to download/analyze in parallel (default 1) |
| `--keep-download DIR` | Keep every download/extraction under DIR |
| `--last N` | Process the last N newly published packages and exit (no loop) |
| `--once` | Single iteration from the persisted state, then exit (no loop, no `time.sleep`) — meant for scheduled jobs (GitHub Actions cron) |
| `--check-ssl`, `--check-http` | Opt-in network enrichment (same as `analyze`) |
| `--json`, `--history-dir PATH`, `--verbose` | Same as `analyze` |

### Exit codes

| Code | Meaning |
|--------|-------------|
| `0` | Analysis completed with no errors |
| `2` | Error (invalid path, read failure, etc.) |

### `--clean` — cache and file cleanup

Global flag that removes nidhogg's persistent data and exits immediately. Doesn't need a subcommand.

| What it cleans | Default path |
|------------|------------------|
| Monitor cache (state, serial) + default history | `.cache/nidhogg/` (includes `.cache/nidhogg/history/`) |
| History at a custom path (if `--history-dir` is passed) | The path passed to `--history-dir` |

```bash
# Cache only
uv run nidhogg.py --clean

# Cache + history
uv run nidhogg.py --clean --history-dir ./history
```

## Website (`site/`)

`site/` is a static frontend (no build step) that displays results in the
browser, with a day selector. Nidhogg doesn't write the files the site
reads directly: it writes the JSONL history first, and a separate script
(`scripts/build_site_data.py`) turns that into `site/data/*.json`.

```bash
# 1. Generate history — pick one (or run several times, it accumulates per day)
uv run nidhogg.py monitor --once          # real new releases from PyPI
uv run nidhogg.py fetch requests          # single package, quick to try out
# both use the default --history-dir: .cache/nidhogg/history

# 2. Regenerate site/data/index.json + site/data/YYYY-MM-DD.json
uv run python scripts/build_site_data.py .cache/nidhogg/history site/data

# 3. Serve and open in the browser
cd site && python3 -m http.server 8000
# open http://localhost:8000
```

Repeat 1→2 and reload the browser — no need to restart the server. If you
used a custom `--history-dir PATH` in step 1, pass that same `PATH` as the
first argument to the script in step 2.

In production this is run automatically by
`.github/workflows/monitor.yml` (cron + `workflow_dispatch`), which commits
`site/data/` and publishes to GitHub Pages. See
[`site/README.md`](site/README.md) for the data schema and
[`docs/deployment-github-actions-pages.md`](docs/deployment-github-actions-pages.md)
for the full deployment design.

## Pipeline

```
walker → [layer1_regex + layer2_ast] → aggregator → enrichment(ssl_cert) → output
```

Both analysis layers run in parallel over every `.py` file. The result is
aggregated and enriched to produce the final findings.

### Layer 1 — Regex

Fast extraction over plain text:

- URLs with a scheme (`http`, `https`, `ftp`, `ws`, `wss`)
- IPv4 in a networking context (calls to `connect`, `urlopen`, `requests`, etc.)
- IPv6 in full and compressed form
- Automatic filtering of private IPs (RFC 1918 + loopback)

### Layer 2 — AST

Static resolution of obfuscated URLs through syntax-tree analysis:

- **Constant folding:** string literals containing a URL
- **Binary concatenation:** `"http://" + "evil.com"` → resolved to the full URL
- **Base64:** `base64.b64decode(Constant)` → decoded and extracted
- **F-strings:** `ast.JoinedStr` with resolvable parts
- **Scope tracking:** following variables assigned before the point of use

### Aggregator

- **URL cleanup:** stripping control characters and non-ASCII, replacing spaces with `%20`
- **URL validation:** rejecting URLs with an invalid scheme/netloc or forbidden characters in the host (`` {}|\^` ``)
- **Deduplication:** keeps the first finding seen for each unique URL
- **Normalization:** lowercased domain, fragments and trailing slashes stripped
- **Benign-domain filtering:** configurable list with wildcard support (`pypi.org` covers `files.pypi.org`)
- **Domain classification:** threat categorization for every remaining URL

### Domain classification

Threat categories evaluated in order:

| Category | Description | Examples |
|-----------|-------------|---------|
| `RAW_IP` | Direct public IP | `185.220.101.x` |
| `SHORTENER` | URL shorteners | `bit.ly`, `tinyurl.com`, `t.co` |
| `TUNNELING` | Exposure tunnels | `ngrok.io`, `workers.dev`, `serveo.net` |
| `EXFILTRATION` | Known exfiltration destinations | `discord.com`, `t.me`, `pastebin.com`, `webhook.site` |
| `IP_RECON` | Public-IP reconnaissance | `ipinfo.io`, `ifconfig.me`, `api.ipify.org` |
| `MALWARE_HOSTING` | Anonymous file hosting | `files.catbox.moe`, `gofile.io` |
| `SUSPICIOUS_TLD` | Risky TLDs | `.tk`, `.ml`, `.zip`, `.xyz`, `.pw` |

### Enrichment

**SSL/TLS (`--check-ssl`):** Connects to port 443 of every HTTPS domain and extracts the certificate issuer.

**HTTP (`--check-http`):** Performs a size-limited GET on every http/https URL found, following redirects, and records the final status and the page title. Findings that get no response at all are dropped from the results.

### History

Each result is appended in JSONL format to `<PATH>/YYYY-MM-DD.jsonl` (`nidhogg/output/history.py`) — `<PATH>` defaults to `.cache/nidhogg/history` under the project directory; `--history-dir` overrides it. Append-only writes; disk/permission failures are logged as a warning and never interrupt the analysis.

## Tests

```bash
uv run pytest
```

| File | What it checks |
|---------|--------------|
| `test_models.py` | Dataclass instantiation and serialization |
| `test_walker.py` | Package walking and file collection |
| `test_layer1_regex.py` | URL and IP detection by regex |
| `test_layer2_ast.py` | Constant folding, base64, f-strings, scope tracking |
| `test_aggregator.py` | Deduplication, normalization, domain filtering |
| `test_domain_classifier.py` | Threat categorization by domain |
| `test_ssl_cert.py` | TLS certificate verification (mocked) |
| `test_http_probe.py` | HTTP probing, page-title extraction, unresponsive-finding pruning |
| `test_file_classifier.py` | File-role tagging (readme, docs, test, packaging, ...) |
| `test_output_writer.py` | JSON serialization and terminal output |
| `test_renderer.py` | Rich terminal rendering |
| `test_cli.py` | `analyze`/`fetch`/`monitor` wiring |
| `test_integration.py` | Full end-to-end pipeline |
| `test_pypi_fetch.py`, `test_changelog.py`, `test_monitor_state.py` | Discovery (`fetching/`) |
| `test_history.py` | Append-only JSONL history |
| `test_build_site_data.py` | `history/*.jsonl` → `site/data/*.json` aggregation |

Code fixtures live in `tests/fixtures/` as real `.py` files organized by scenario:

- `pkg_basic/` — literal URLs, concatenation, dynamic execution
- `pkg_obfuscated/` — base64, f-strings, scope tracking
- `pkg_malicioso/` — realistic mix of URLs + dynamic execution

### Code quality

```bash
uv run ruff check       # linting
uv run ruff format      # formatting
uv run mypy             # strict type checking
```

## Architecture

```
nidhogg/
├── core/
│   ├── models.py               # Shared dataclasses (PackageAnalysis, UrlFinding, etc.)
│   └── exceptions.py           # Project-specific exceptions
├── analysis/
│   ├── walker.py               # Main entry point: orchestrates a package's analysis
│   ├── file_classifier.py      # File tagging by path/name (readme, docs, test, packaging, ...)
│   ├── layer1_regex.py         # Layer 1: regex extraction over plain text
│   ├── layer2_ast.py           # Layer 2: constant folding, base64, f-strings, scope tracking
│   ├── aggregator.py           # Deduplication, normalization, and domain classification
│   └── domain_classifier.py    # Threat categorization by domain/IP
├── enrichment/
│   ├── ssl_cert.py             # TLS certificate verification
│   └── http_probe.py           # HTTP probing: response status and page title
├── fetching/
│   ├── pypi_fetch.py           # Download + safe extraction of a single PyPI package
│   ├── changelog.py            # PyPI XML-RPC changelog client (new releases)
│   └── monitor_state.py        # Persists the last serial processed by `monitor`
├── output/
│   ├── writer.py               # JSON serialization and terminal output
│   └── history.py              # Append-only JSONL history (--history-dir)
├── cli.py                      # CLI entry point: analyze / fetch / monitor
└── data/
    ├── suspicious_domains.toml # Threat domains by category
    └── benign_domains.txt      # ~100 legitimate domains

scripts/
└── build_site_data.py          # history/*.jsonl → site/data/*.json + index.json

site/                           # Static frontend (see "Website" above)
├── index.html, style.css, app.js
└── data/                       # Generated by scripts/build_site_data.py, not by hand
```
