# CTI Dashboard technical guide

This guide describes the current data pipeline, dashboard, public chat assistant, local development workflow, and Azure VM deployment.

## 1. Architecture

The application has three main parts:

1. **Collectors and pipeline:** Python modules fetch public threat-intelligence data, normalize it, enrich selected records, and write JSON files.
2. **Dashboard:** Static HTML, CSS, and JavaScript render those JSON files in a browser. No frontend framework or database is required.
3. **Chat API:** A small Python HTTP service reads the dashboard data and sends a bounded, read-only context to Azure OpenAI. It uses the VM's managed identity; credentials are not placed in browser JavaScript.

In production, a systemd timer starts the collection pipeline every 15 minutes. Each feed independently observes its configured collection interval. Nginx serves the static site and JSON files, and proxies HTTPS chat requests to the API bound to localhost.

## 2. Repository map

| Path | Responsibility |
|---|---|
| `collectors/` | One module per feed or enrichment source; each provides `FEED` metadata and collection helpers. |
| `pipeline/run.py` | Schedules due feeds, merges and deduplicates records, prunes old data, enriches vulnerabilities, and writes dashboard JSON. |
| `pipeline/make_samples.py` | Generates illustrative sample data for offline demonstrations and tests. |
| `pipeline/weekly_report.py` | Produces a Markdown weekly threat-landscape summary from the generated data. |
| `api/chat.py` | Validates public chat requests, selects relevant dashboard records, gets a managed-identity token, and calls Azure OpenAI. |
| `web/` | Static dashboard markup, styling, filtering, rendering, and chat UI. |
| `data/` | Runtime output and persisted collector state; `data/samples/` contains committed sample data. |
| `deploy/` | Nginx, systemd, environment examples, install and hardening scripts. |
| `docs/` | Schema, feed catalogue, operational runbook, ethics, and stakeholder/function documentation. |
| `tests/` | Pipeline, collector, and chat API tests. |

## 3. Data sources and dashboard features

The pipeline registers these record feeds in `pipeline/run.py`:

- **CISA Known Exploited Vulnerabilities (KEV):** known exploited CVEs and remediation information.
- **TridentStack CVE catalogue:** paginated CVE entries mapped into the vulnerability schema. The collector persists its cursor and request timestamps, limits itself to 50 API requests per rolling hour, and resumes pagination in a later run when capped.
- **CISA All Advisories:** advisory records are exposed under the historical feed ID `acsc`.
- **abuse.ch ThreatFox and URLhaus:** threat indicators and malware infrastructure metadata.
- **ransomware.live:** publicly posted ransomware victim records.
- **Security news wires:** headline, source, link, and publication metadata from the configured RSS sources.

Enrichment/reference sources include **FIRST EPSS**, **NIST NVD**, and **MITRE ATT&CK Enterprise**. Sources and retained fields are listed in `docs/feed-catalogue.md`; upstream availability, terms, rate limits, and coverage can change.

The dashboard provides:

- Seven-day summary tiles and an aggregate feed-health indicator.
- Vulnerability prioritization, including KEV, EPSS, CVSS, ransomware-related tags, and remediation information where supplied.
- Panels for advisories, ransomware incidents, infostealer indicators, other indicators, ATT&CK groups/techniques, news, and per-feed status.
- Search across records and a severity filter; panels display freshness based on the last successful collection.
- A responsive floating chat bubble in the lower-right corner; it opens a compact, non-modal assistant window without covering or reflowing dashboard panels.
- A public, read-only CTI assistant with source links and the dashboard snapshot timestamp.

Infostealer information is metadata-only. The project is designed not to retain or display stolen usernames, passwords, cookies, tokens, or personal identifiers.

## 4. Pipeline and data contract

The main entry point is `python -m pipeline.run`. It reads and writes to `CTI_DATA_DIR` when configured; otherwise it uses the repository's `data/` directory.

Useful modes:

```bash
python -m pipeline.run                 # run feeds that are due
python -m pipeline.run --all            # force all record feeds and enrichment
python -m pipeline.run --feeds kev nvd  # run selected record feeds now
python -m pipeline.run --sample         # build outputs from local sample data
```

The pipeline:

1. Loads records and per-feed metadata.
2. Runs due feeds (or the selected/forced feeds), records feed health, and merges results using `(feed, id)` as the deduplication key.
3. Preserves `first_seen` when a refreshed record replaces an existing record.
4. Enriches CVE records using EPSS and NVD data, refreshes ATT&CK reference data, and calculates a vulnerability priority score.
5. Prunes records according to type-specific retention, except KEV records, and caps stored records at 5,000.
6. Writes `records.json`, `meta.json`, and `summary.json` using temporary files followed by atomic replacement.

The canonical record format and feed-specific metadata are documented in `docs/schema.md`. Important outputs are:

| File | Purpose |
|---|---|
| `records.json` | Normalized, deduplicated, enriched records, newest first. |
| `meta.json` | Feed status, last run/success, interval, count, and any error. |
| `summary.json` | Dashboard totals, seven-day metrics, and feed-health counts. |
| `attack.json` | MITRE ATT&CK technique and group reference tables. |
| `epss.json`, `nvd.json` | Local enrichment caches. |

Indicators, news, incidents, advisories, and vulnerabilities use different retention periods; KEV records are exempt from age pruning. Refer to `pipeline/run.py` for the current retention constants.

## 5. Frontend and chat request flow

The static browser app reads `/data/records.json`, `/data/meta.json`, `/data/summary.json`, and `/data/attack.json`, refreshing the dashboard periodically. Browser-side search and severity filtering operate on the loaded data. Feed-provided text is escaped before it is rendered as HTML.

The assistant opens from a fixed-position chat bubble and can be closed without losing the current conversation. Its compact window includes a collapsible recent-thread list and a new-conversation action. Threads are stored in the user's browser local storage (up to 20 threads and 30 messages per thread); they are not synced to the server or shared between browsers. Users can delete saved threads. Assistant markdown is rendered with DOM nodes and text content rather than injecting model output as HTML; supported formatting includes headings, lists, emphasis, links over HTTPS, inline code, and fenced code blocks.

Chat follows a separate server-side path:

1. The browser sends the question as JSON to `/api/chat` over HTTPS. No user login is required.
2. Nginx applies request limits and proxies to the API on `127.0.0.1:8000`.
3. The API validates the request, reads dashboard JSON from `CTI_DATA_DIR`, selects up to 12 relevant records, and bounds the context size.
4. The API requests an Azure AI token using the VM's managed identity and calls the configured Azure AI Foundry deployment through the Responses API. It sends at most the last four conversation messages and bounds source records and output tokens.
5. Only a question matching `Explain CVE-YYYY-NNNN` triggers an external NIST NVD lookup; other questions use local dashboard data only. The response includes the answer, source records, and snapshot timestamp. The browser only links to HTTPS source URLs.

The assistant is instructed to answer only from the provided dashboard snapshot, treat feed content as untrusted data rather than instructions, and say when the context does not answer a question. It is not a general browsing tool, incident-response system, or action-taking agent. The API does not log question bodies.

The API limits request bodies to 8 KiB, questions and history messages to 1,000 characters, and conversation context to four prior messages. Model output is capped at 400 tokens. Feed health and seven-day summaries are only included in model context for questions about those topics. Nginx applies per-client throttling, a global chat limit of five requests per minute (with a small burst), and a single concurrent chat request. These controls reduce, but do not eliminate, public-service abuse or model costs.

## 6. Local development

### Prerequisites

- Python 3.11 or later recommended.
- Git.
- Node.js only if you want to run the JavaScript syntax check.

Create and activate a virtual environment, then install development dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

On Linux/macOS, activate with `. .venv/bin/activate`.

### Offline dashboard

```powershell
python -m pipeline.make_samples
python -m pipeline.run --sample
New-Item -ItemType SymbolicLink -Path .\web\data -Target ..\data -Force
python -m http.server 8000 --directory web
```

Open `http://localhost:8000`. The static dashboard works with sample data without feed API keys. If creating a Windows symlink is restricted, use an equivalent local directory junction or copy the generated JSON files into `web\data`.

The Azure chat API is a separate server component and is not provided by Python's static file server. Local chat requires a separately configured API environment and Azure authentication; the production configuration is described below.

### Live collection

Copy `deploy/env.example` to a protected environment file or set variables in the shell. Configure `CTI_DATA_DIR`, and add feed credentials such as `ABUSECH_API_KEY` and `NVD_API_KEY` where required. Never commit real secrets.

```powershell
$env:ABUSECH_API_KEY = "..."
$env:NVD_API_KEY = "..."
python -m pipeline.run --all
```

Later, `python -m pipeline.run` observes the configured feed intervals. Upstream sources may impose rate limits or be temporarily unavailable; inspect `meta.json` for per-feed status.

### Tests

```powershell
pytest -q
```

Tests cover the common data contract, sample pipeline, collectors, privacy constraints, and chat API behavior. Some pipeline tests regenerate data samples/outputs, so inspect `git status` after running tests before staging changes.

## 7. Azure VM deployment

The deployment target is an Ubuntu VM. `deploy/harden.sh`, `deploy/install.sh`, systemd units, and `deploy/nginx.conf` configure the services. The installer synchronizes the checkout to `/srv/cti/app`, installs Python dependencies in a virtual environment, configures systemd and Nginx, and starts collection.

Production services:

- `cti-collect.timer` invokes the collection service every 15 minutes; each feed still respects its own interval.
- `cti-report.timer` schedules weekly report generation.
- `cti-chat.service` runs the API as the unprivileged `cti` user, with working directory `/srv/cti/app`.
- Nginx serves `/srv/cti/app/web` and exposes `/srv/cti/data` read-only under `/data/`.
- Certbot can configure the TLS virtual host and redirect HTTP to HTTPS. Azure NSG rules must allow inbound TCP 80/443; SSH should be restricted to trusted source addresses.

### Azure OpenAI setup

1. Enable the VM's system-assigned managed identity.
2. Grant that identity model inference access to the Foundry resource hosting the deployment (for example, the **Azure AI User** role where applicable).
3. Put the resource endpoint and exact model **deployment name** in `/etc/cti/env`:

   ```env
   AZURE_OPENAI_ENDPOINT=https://<resource-name>.services.ai.azure.com/openai/v1
   AZURE_OPENAI_DEPLOYMENT=gpt-5-mini
   ```

4. Install/update the application and restart the API:

   ```bash
   sudo bash /srv/cti/checkout/deploy/install.sh
   sudo systemctl restart cti-chat.service
   ```

5. Verify the service locally using `curl -i http://127.0.0.1:8000/health`, then test chat through the HTTPS site.

The deployment value is the exact deployment name shown in Foundry, not the project name. The endpoint may be the resource root (`https://<resource-name>.services.ai.azure.com`) or the `/openai/v1` base URL; the API normalizes either form. This implementation obtains a token for `https://ai.azure.com/.default` and posts to the Responses API. Store no Azure key in browser code or in the repository. Public chat can incur model usage costs; monitor Azure consumption and set a budget alert.

## 8. Adding a collector

1. Add `collectors/<id>.py` following a similar module and define complete `FEED` metadata.
2. Implement collection using `collectors/base.py` helpers and return common-schema records.
3. Add the feed to `RECORD_FEEDS` in `pipeline/run.py`.
4. Add illustrative sample data and tests.
5. Document source terms and retained fields in `docs/feed-catalogue.md`.
6. Review privacy, legality, and ethics; update `docs/ethics-register.md` when relevant.
7. Run tests and inspect generated changes before committing.

## 9. Troubleshooting

| Symptom | Checks |
|---|---|
| Dashboard panels empty | Confirm JSON files exist under the configured data directory, Nginx can read them, and `/data/records.json` returns JSON. |
| Feed marked error or stale | Inspect `meta.json`, `journalctl -u cti-collect`, credentials, source availability, and rate limits. |
| Chat says HTTPS is required | Open the site with HTTPS and confirm the certificate covers the hostname. |
| Chat returns 502 | Check `systemctl status cti-chat.service`, `journalctl -u cti-chat.service`, Nginx error logs, and the Azure endpoint/deployment configuration. |
| Chat returns 503 | Check that `AZURE_OPENAI_ENDPOINT` and `AZURE_OPENAI_DEPLOYMENT` are set, dashboard JSON is readable, and the VM identity can obtain a token. |
| Chat works locally but not through Nginx | Check the Nginx route, TLS server block, rate-limit status, and that the API is listening at `127.0.0.1:8000`. |

Useful VM commands:

```bash
sudo systemctl status cti-collect.timer cti-chat.service --no-pager
sudo journalctl -u cti-collect -n 100 --no-pager
sudo journalctl -u cti-chat.service -n 100 --no-pager
sudo nginx -t
curl -i http://127.0.0.1:8000/health
curl -s https://<host>/data/meta.json
```

Never paste `/etc/cti/env` contents into logs, tickets, or chat; it can contain feed secrets.

## 10. Privacy, security, and operational limits

- The dashboard aggregates third-party public intelligence; it is not a substitute for source validation or analyst review.
- Feed data may be stale, incomplete, inaccurate, or unavailable. Use source links and timestamps when making decisions.
- Infostealer data is limited to metadata; credential-like content and personal identifiers are not intended to be stored or displayed.
- Chat is publicly accessible by design and has no user identity or per-user authorization. HTTPS and request limits are required, but rate limiting alone is not a complete cost-control solution.
- Managed identity keeps Azure OpenAI authentication server-side. Do not put keys in HTML, JavaScript, or committed configuration.
- The chat assistant is read-only and context-limited; it does not execute commands, query arbitrary URLs, or take remediation actions.

## 11. Reference documentation

- `docs/schema.md` — record schema and feed-specific fields.
- `docs/feed-catalogue.md` — source formats, terms, and retained fields.
- `docs/runbook.md` — operational checks and incident procedures.
- `docs/ethics-register.md` and `docs/hardening-checklist.md` — data handling and deployment safeguards.
- `docs/functional.md` — business stakeholder description and advantages.
