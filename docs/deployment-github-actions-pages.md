# Deployment on GitHub Actions + GitHub Pages

Guide to **how** to set up Nidhogg to run periodically via GitHub Actions
and publish its results to a GitHub Pages site. This is design/operations
documentation, not an implementation plan — it doesn't include tasks or
production code yet.

## Architecture overview

```
┌─────────────────┐   cron    ┌──────────────────────┐
│ GitHub Actions   │ ────────▶│ Job: nidhogg monitor  │
│ (schedule)       │           │  --once               │
└─────────────────┘           └──────────┬────────────┘
                                          │ analyzes new PyPI releases
                                          ▼
                               ┌──────────────────────┐
                               │ .cache/nidhogg/       │  commit to repo
                               │ monitor_state.json     │◀────────────┐
                               │ history/YYYY-MM-DD.jsonl│             │
                               └──────────┬────────────┘              │
                                          │ 1 jsonl → 1 json per day   │
                                          ▼                            │
                               ┌──────────────────────┐               │
                               │ site/data/YYYY-MM-DD.json│            │
                               │ site/data/index.json  │──────────────┘
                               └──────────┬────────────┘
                                          │ upload-pages-artifact
                                          ▼
                               ┌──────────────────────┐
                               │ GitHub Pages           │
                               │ site/index.html + JS   │
                               └──────────────────────┘
```

Each workflow run: discovers new PyPI releases since the last persisted
point, analyzes them, appends the result to **today's** JSONL history
(`history/YYYY-MM-DD.jsonl` — already accumulates every run of the day, no
changes needed in `nidhogg/output/history.py`), regenerates the per-day
JSON files + the index, commits state+history to the repo, and publishes
the updated static site.

## `monitor`'s `--once` mode

`nidhogg monitor` has three modes:

- **Continuous loop** (`--interval`): uses the `last_serial` persisted in
  `--index-file` as a starting point, but runs forever — doesn't fit an
  Actions job that starts and finishes.
- **`--last N`**: exits after processing the last N packages, but
  **ignores the persisted `last_serial` when reading** — it only writes it
  at the end. Good for "just give me the last 10", bad for "continue
  exactly where I left off last time" — with a poorly calibrated N,
  releases get duplicated or skipped.
- **`--once`** *(implemented)*: a single iteration from the persisted
  `last_serial`, saves the new state, and exits — no loop, no
  `time.sleep`. This is the mode this document's workflow uses:

```
nidhogg monitor --once [--index-file PATH] [--history-dir PATH] ...
```

Implementation: `_run_monitor_once` in `nidhogg/cli.py` reuses
`_run_monitor_iteration_plain/rich` + `save_state`, calling them once
without the loop's `_wait_before_next_poll_rich`/`time.sleep`. It doesn't
touch `changelog.py` or `monitor_state.py`.

## GitHub Actions workflow

`.github/workflows/monitor.yml` (full example):

```yaml
name: Monitor PyPI

on:
  schedule:
    - cron: "*/15 * * * *"   # every 15 min; GH doesn't guarantee exact punctuality
  workflow_dispatch: {}       # allows manual trigger from the UI

permissions:
  contents: write   # commit state + history
  pages: write      # publish to Pages
  id-token: write   # required by actions/deploy-pages

concurrency:
  group: "monitor-pypi"
  cancel-in-progress: false   # never overlap two runs on the same state

jobs:
  monitor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v3
        with:
          python-version: "3.14"

      - run: uv sync --frozen

      - name: Run monitor (single iteration)
        run: |
          uv run nidhogg monitor --once \
            --history-dir history \
            --index-file .cache/nidhogg/monitor_state.json

      - name: Regenerate per-day JSON + index
        run: uv run python scripts/build_site_data.py history site/data

      - name: Commit state + history
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add .cache/nidhogg/monitor_state.json history/ site/data/
          git diff --staged --quiet || git commit -m "chore: monitor run $(date -u +%Y-%m-%dT%H:%M:%SZ)"
          git push

      - uses: actions/upload-pages-artifact@v3
        with:
          path: site

  deploy:
    needs: monitor
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - id: deployment
        uses: actions/deploy-pages@v4
```

Things to keep in mind:

- **`concurrency.cancel-in-progress: false`** — if a run takes longer than
  the cron interval, the next one must wait, not cancel the one that's
  writing state (avoids race conditions on `monitor_state.json`).
- **`git push` can fail** if something else wrote to the repo between
  checkout and push (unlikely in a repo with a single workflow writing,
  but a retry policy needs deciding — `git pull --rebase` + retry, or let
  it fail and have the next tick pick it up).
- **Cron frequency**: with no VT involved there's no longer an external
  rate limit to respect (see the `CLAUDE.md` cleanup — VT isn't used).
  The real limit is [PyPI's changelog API](https://pypi.org/) (reasonable
  use) and GitHub Actions' minimum (`*/5` is the minimum supported, but it
  can be delayed under platform load).
- **Secrets**: none needed — neither the PyPI JSON API nor the XML-RPC
  changelog require authentication.

## Aggregating results: `scripts/build_site_data.py`

Script (not implemented yet) that walks `history/*.jsonl` (one line = one
`build_document()` per package, already partitioned by day by
`nidhogg/output/history.py:append_finding`) and produces **one JSON file
per day** plus an index, instead of a single aggregate — this lets the
site filter by date without loading the whole history at once:

```
site/data/
├── index.json          # list of available dates + generated_at
├── 2026-07-17.json      # same shape as before, scoped to that day
├── 2026-07-16.json
└── ...
```

`index.json`:

```json
{
  "generated_at": "2026-07-17T12:00:00Z",
  "latest": "2026-07-17",
  "dates": ["2026-07-17", "2026-07-16", "2026-07-15"]
}
```

`site/data/2026-07-17.json` (identical to the historical `results.json`
schema, just already trimmed to one day):

```json
{
  "generated_at": "2026-07-17T12:00:00Z",
  "stats": {
    "total_packages": 84,
    "malicious": 2,
    "clean": 82
  },
  "packages": [
    {
      "name": "some-pkg",
      "analyzed_at": "2026-07-17T11:58:03Z",
      "total_findings": 3,
      "findings": [
        {
          "url": "http://evil.example/payload",
          "file": "setup.py",
          "line": 42,
          "layer": "ast",
          "method": "base64",
          "domain_threat": "exfiltration"
        }
      ]
    }
  ]
}
```

Per-date transformation: `history/2026-07-17.jsonl` →
`site/data/2026-07-17.json` is nearly 1:1 (parse each line, wrap in
`{generated_at, stats, packages}`, compute `stats` over that subset). No
dedup or merge across dates needed — each `.jsonl` is already an isolated
day. The script simply reprocesses **all** `history/*.jsonl` files present
on each run (cheap, small files, no incremental state to maintain) and
regenerates `index.json` at the end. No retention limit for now: the
files are small and per-day, so there's no single artifact that grows
unbounded — revisit if the history ever becomes heavy in the repo.

## Frontend: the site in `site/`

```
site/
├── index.html      # structure + references to style.css/app.js
├── style.css        # theme, risk badges, responsive layout
├── app.js            # fetches data/index.json + data/<day>.json, renders
└── data/
    ├── index.json     # available dates, generated by the workflow
    └── YYYY-MM-DD.json  # one file per day, generated by the workflow
```

No build step (no npm/node in the pipeline) — plain HTML/CSS/JS served
as-is by Pages. Recommended elements to make it "appealing":

- **Header with stats**: total analyzed, number malicious, last update
  (`generated_at`), dashboard-style.
- **Package table/grid**: name, date, number of findings.
- **Client-side search** (by name) — the whole day's dataset is already
  in memory via `fetch`, no backend needed.
- **Day selector**: `data/index.json` feeds a `<select>`/date-picker; on
  change, fetch `data/<date>.json` and re-render table+spine+stats scoped
  to that day. Default = `latest`. Pending implementation in `app.js`
  (today it only fetches a single `results.json`).
- **Expandable detail** per package: list of `findings` with URL, file,
  line, layer (`regex`/`ast`), method, and `domain_threat`.
- **Dark mode** via `prefers-color-scheme`, consistent with the rest of
  the design conventions already used in the project for artifacts.
- If charts get added later (findings per day, `domain_threat`
  distribution), follow the project's `dataviz` skill for a consistent
  palette and style — doesn't apply yet since there are no charts in this
  first version.

## Setup checklist

1. ~~Implement `monitor --once` in `cli.py`~~ — done.
2. ~~Write `scripts/build_site_data.py`~~ — done (per-day JSON +
   `index.json`).
3. Migrate `site/app.js` to the day selector (`index.json` + fetch per
   date) — pending.
4. Enable GitHub Pages in Settings → Pages → Source: **GitHub Actions**
   (not "Deploy from a branch" — we use `actions/deploy-pages`).
5. ~~Add `.github/workflows/monitor.yml`~~ — done.
6. Manual trigger (`workflow_dispatch`) to validate the first run before
   leaving the cron active — pending, to do in GitHub after enabling
   Pages.
7. Review after the first run: `monitor_state.json` committed, `history/`
   with at least one JSONL file, `site/data/index.json` +
   `site/data/YYYY-MM-DD.json` generated, site published and reachable at
   `https://<user>.github.io/<repo>/`.

## Out of scope for this document

- Doesn't cover the day selector in `app.js` yet (today it only consumes
  a single file) — implementation pending.
- Doesn't cover long-term history retention (are old days ever deleted
  from `history/`/`site/data/`? — not a problem while the repo stays
  light, revisit if needed).
- Doesn't cover alerting (e.g. an automatic issue/Slack message when a
  `malicious` verdict appears).
- Doesn't cover what happens if `git push` fails due to a conflict —
  retry policy to be defined when the implementation plan is written.
