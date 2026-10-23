"""FIRST EPSS scores. Not a record feed: it produces an enrichment table {cve: {epss, percentile}}.

The pipeline calls `enrich_table(ctx, cves)` for the CVEs it already holds, so we only
query what we need instead of downloading the full daily CSV (250k rows).
"""
from .base import get, load_sample

FEED = {
    "id": "epss",
    "name": "FIRST EPSS",
    "category": "enrichment",
    "url": "https://api.first.org/data/v1/epss",
    "licence": "FIRST, free for use with attribution",
    "interval_minutes": 1440,
}

BATCH = 100


def collect(ctx):
    # Record feed contract: EPSS contributes no records of its own.
    return []


def enrich_table(ctx, cves: list[str]) -> dict:
    if ctx.sample_mode:
        return {row["cve"]: row for row in load_sample(ctx, "epss")}
    table = {}
    cves = sorted(set(c for c in cves if c))
    for i in range(0, len(cves), BATCH):
        chunk = cves[i:i + BATCH]
        r = get(ctx, FEED["url"], params={"cve": ",".join(chunk)})
        for row in r.json().get("data", []):
            table[row["cve"]] = {
                "cve": row["cve"],
                "epss": float(row.get("epss", 0)),
                "percentile": float(row.get("percentile", 0)),
                "date": row.get("date"),
            }
    return table
