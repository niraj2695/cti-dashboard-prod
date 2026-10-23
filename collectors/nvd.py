"""NVD CVE API 2.0: CVSS enrichment for the CVEs we already hold (KEV and others).

Set NVD_API_KEY in the environment to lift the rate limit from 5 to 50 requests per 30 s.
Like EPSS this is an enrichment table, not a record feed.
"""
import time

from .base import get, load_sample

FEED = {
    "id": "nvd",
    "name": "NIST NVD CVE API 2.0",
    "category": "enrichment",
    "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "licence": "NIST, public domain; attribution requested",
    "interval_minutes": 1440,
}

MAX_LOOKUPS = 150  # per run: KEV adds a handful of CVEs a day, keep well under the limit


def collect(ctx):
    return []


def _cvss(metrics: dict):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            d = metrics[key][0]["cvssData"]
            return d.get("baseScore"), d.get("baseSeverity", "").lower() or None, key
    return None, None, None


def enrich_table(ctx, cves: list[str], known: dict | None = None) -> dict:
    """Return {cve: {cvss, cvss_severity, cvss_version, description}}.
    `known` is the previous table so we skip CVEs already looked up."""
    if ctx.sample_mode:
        return {row["cve"]: row for row in load_sample(ctx, "nvd")}
    known = dict(known or {})
    todo = [c for c in sorted(set(cves)) if c not in known][:MAX_LOOKUPS]
    headers = {}
    if ctx.secret("NVD_API_KEY"):
        headers["apiKey"] = ctx.secret("NVD_API_KEY")
    delay = 0.7 if headers else 6.5
    for cve in todo:
        try:
            r = get(ctx, FEED["url"], params={"cveId": cve}, headers=headers)
            vulns = r.json().get("vulnerabilities", [])
            if vulns:
                c = vulns[0]["cve"]
                score, sev, ver = _cvss(c.get("metrics", {}))
                desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
                known[cve] = {"cve": cve, "cvss": score, "cvss_severity": sev,
                              "cvss_version": ver, "description": desc[:400]}
        except RuntimeError:
            continue
        time.sleep(delay)
    return known
