# CTI Dashboard technical guide

This document describes how the project is structured, how the data pipeline works, and how to run it locally for development or offline demos.

## 1. Project overview

`cti-dashboard` is a Python-based cyber threat intelligence dashboard that aggregates public CTI feeds, normalises the records into a shared schema, enriches them with data such as EPSS and CVSS, and serves the results as a static frontend.

The project is intentionally lightweight:

- Python pipeline for collection and enrichment
- static HTML/CSS/JavaScript dashboard
- JSON files in `data/` as the contract between pipeline and UI
- no framework or database required

The main production flow is:

1. Collect records from multiple sources
2. Merge and deduplicate them
3. Enrich vulnerability records with EPSS/NVD data
4. Refresh ATT&CK reference tables
5. Save JSON outputs to `data/`
6. Serve the results via static web assets

## 2. Key responsibilities by folder

### `collectors/`

Each source is implemented as a standalone module.

Examples:

- `collectors/kev.py` - CISA KEV vulnerabilities
- `collectors/nvd.py` - NVD enrichment data
- `collectors/attack.py` - MITRE ATT&CK reference tables
- `collectors/news.py` - news wires
- `collectors/urlhaus.py` and `collectors/threatfox.py` - malicious infrastructure / indicators

Each collector module is expected to expose:

- `FEED` metadata
- `collect(ctx)` returning a list of records

The shared base API lives in `collectors/base.py` and defines:

- common `Context` object
- HTTP helper functions (`get`, `post`)
- date parsing helpers
- record construction helpers
- schema conventions

### `pipeline/`

This layer coordinates the operational work.

- `pipeline/run.py` is the main pipeline entry point
- `pipeline/make_samples.py` creates illustrative offline sample data
- `pipeline/weekly_report.py` is part of the reporting workflow for generated summaries

The pipeline manages:

- feed scheduling based on `interval_minutes`
- per-feed health in `meta.json`
- deduplication keyed on `(feed, id)`
- record pruning and retention
- summary generation

### `web/`

The frontend is a static dashboard:

- `index.html` defines the panels and layout
- `app.js` loads `data/*.json` and renders the UI
- `style.css` contains dashboard styling

The browser does not fetch from an API server. It reads the generated JSON directly.

### `data/`

This is the runtime data directory.

- `data/records.json` - merged, deduplicated, enriched records
- `data/meta.json` - feed health and timestamps
- `data/summary.json` - dashboard tile stats and counts
- `data/attack.json`, `data/epss.json`, `data/nvd.json` - enrichment/reference tables
- `data/samples/` - committed sample data used for offline mode and tests

### `tests/`

The test suite validates the core contract the dashboard depends on.

Relevant checks include:

- record schema is valid
- there are no duplicate feed+ID combinations
- records are sorted newest-first
- KEV records are enriched with EPSS, CVSS, and priority values
- infostealer data remains metadata-only

## 3. Common record schema

The shared schema is defined in `docs/schema.md` and enforced by the pipeline.

A record has the shape:

```python
{
  "id": "...",
  "type": "vulnerability",
  "feed": "kev",
  "title": "...",
  "summary": "...",
  "url": "...",
  "published": "2026-10-19T12:00:00Z",
  "severity": "high",
  "tags": ["vendor", "product"],
  "extra": {},
  "first_seen": "2026-10-19T12:30:00Z"
}
```

Record types include:

- `vulnerability`
- `advisory`
- `indicator`
- `incident`
- `news`
- `technique`

The `extra` field differs per feed, but is intentionally free-form so each collector can carry source-specific metadata without changing the dashboard contract.

## 4. Data flow and processing model

The core pipeline is implemented in `pipeline/run.py`.

### Feed selection

The default run uses the tracked feed list:

```python
RECORD_FEEDS = ["kev", "acsc", "threatfox", "urlhaus", "ransomwarelive", "news"]
ENRICH_FEEDS = ["epss", "nvd", "attack"]
```

The pipeline only fetches feeds whose `interval_minutes` has elapsed unless `--all` is used.

### Merge and dedupe

Each collected feed is merged into the existing record list using a dedupe key of `(feed, id)`. Fresh records replace previous ones, preserving the original `first_seen` if the record already existed.

This approach keeps the dashboard stable even when feed sources update or re-publish the same record.

### Retention and pruning

The pipeline prunes older records by type:

- `indicator`: 14 days
- `news`: 30 days
- `incident`: 90 days
- `advisory`: 180 days
- `vulnerability`: 365 days
- KEV records are never pruned

It also caps the total number of stored records at `MAX_RECORDS = 5000`.

### Enrichment

For vulnerability records with a CVE, the pipeline adds:

- EPSS score / percentile
- NVD CVSS / severity
- ATT&CK reference tables
- priority score used by the KEV panel

The priority formula is computed in `pipeline/run.py`:

```python
score = 0.0
if r["extra"].get("kev"):
    score += 50
score += 40 * float(r["extra"].get("epss", 0))
score += float(r["extra"].get("cvss") or 0)
if "ransomware" in r["tags"]:
    score += 10
```

This matters because the dashboard surfaces high-priority exposures as the most actionable alerts.

## 5. Local development setup

### Prerequisites

- Python 3.11+ recommended
- Git
- Access to a terminal

### Windows PowerShell setup

From the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

### Linux/macOS shell setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

## 6. Running the project locally

### Offline mode (recommended for first run)

This mode uses bundled sample data and does not require network access or API keys.

```powershell
python -m pipeline.make_samples
python -m pipeline.run --sample
```

Then serve the static dashboard:

```powershell
New-Item -ItemType SymbolicLink -Path .\web\data -Target ..\data -Force
python -m http.server 8000 --directory web
```

Open:

- `http://localhost:8000`

If you create the symlink is not possible in PowerShell due to permissions, copy or link the folder manually. The dashboard expects the JSON files under `web/data/*.json`.

### Live data mode

For real feed collection, set environment variables and run the pipeline.

1. Copy the deploy example file:

```powershell
Copy-Item .\deploy\env.example .\.env
```

2. Fill in secrets in `.env` or set them in your shell environment.

Required or useful values include:

- `ABUSECH_API_KEY`
- `NVD_API_KEY`
- `CTI_DATA_DIR`
- `CTI_USER_AGENT`

3. Load the environment and run:

```powershell
$env:ABUSECH_API_KEY = "..."
$env:NVD_API_KEY = "..."
python -m pipeline.run --all
```

The first live run may take a while because NVD rate limits are enforced.

After that, a normal run uses intervals:

```powershell
python -m pipeline.run
```

## 7. Running tests

```powershell
pytest -q
```

The test suite validates the sample pipeline and the contract between the pipeline and the dashboard.

## 8. Adding a new collector

The project expects a consistent collector pattern.

1. Copy a similar existing collector, such as `collectors/acsc.py`
2. Create `collectors/<id>.py`
3. Define `FEED` metadata (id, name, category, interval, licence, URL)
4. Implement `collect(ctx)` returning records in the common schema
5. Add sample data in `data/samples/<id>.json` or extend `pipeline/make_samples.py`
6. Register the feed in `pipeline/run.py` under `RECORD_FEEDS`
7. Document the feed in `docs/feed-catalogue.md`
8. Add an ethics/legal note if it contains infostealer or personal-risk data

Use `collectors/base.py` helpers rather than re-implementing parsing logic.

## 9. Security and ethics notes

This project intentionally enforces a privacy-safe design:

- infostealer indicators are treated as metadata only
- usernames, passwords, cookies, session tokens, and personal identifiers are not stored or displayed
- panel labels make the source clear
- legal and ethical documentation is maintained in `docs/ethics-register.md` and `docs/feed-catalogue.md`

The build will fail if infostealer-related data begins to contain credential-like content.

## 10. Production deployment model

The repository contains deployment examples for hardened server operation under `deploy/`.

Key files:

- `deploy/install.sh`
- `deploy/harden.sh`
- `deploy/nginx.conf`
- `deploy/cti-collect.service`
- `deploy/cti-collect.timer`
- `deploy/env.example`

The design is a static file server in front of generated data JSON files. The pipeline runs as a scheduled service and writes to a dedicated data directory, while Nginx exposes that data read-only.

## 11. Troubleshooting

### Missing JSON files in the browser

Ensure that `web/data` points to the generated dataset directory and that `records.json`, `meta.json`, `summary.json`, and `attack.json` exist.

### Pipeline fails in offline mode

Run:

```powershell
python -m pipeline.make_samples
python -m pipeline.run --sample
```

### Real feed errors

Check the feed health in `data/meta.json` and inspect the `error` field for the failing source. Many feed issues are caused by rate limits, API key problems, or malformed source data.

### Tests fail

Recreate the sample environment cleanly:

```powershell
python -m pipeline.make_samples
python -m pipeline.run --sample
pytest -q
```

## 12. Quick reference

Useful commands:

```powershell
# install dependencies
pip install -r requirements-dev.txt

# generate offline data
python -m pipeline.make_samples
python -m pipeline.run --sample

# run the website locally
python -m http.server 8000 --directory web

# run tests
pytest -q

# run all feeds (live)
python -m pipeline.run --all

# run only due feeds
python -m pipeline.run
```

## 13. Summary

`cti-dashboard` is a compact but practical CTI project that demonstrates how to:

- collect multiple intelligence feeds
- normalise them into a single schema
- maintain feed health and freshness
- enrich data with common CTI sources
- serve a useful operational dashboard from static assets

The project is intentionally simple and transparent, which makes it a useful reference implementation for CTI pipeline patterns and frontend data consumption.

