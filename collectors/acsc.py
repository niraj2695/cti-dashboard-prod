"""ACSC (cyber.gov.au) alerts and advisories RSS.

The feed URL has moved more than once; verify it in Week 1 and update here.
"""
from .base import get, load_sample, parse_rss, rss_to_records

FEED = {
    "id": "acsc",
    "name": "ACSC Advisories",
    "category": "advisory",
    "url": "https://www.cyber.gov.au/rss/advisories",
    "licence": "Commonwealth of Australia, CC BY 4.0 (verify on site)",
    "interval_minutes": 60,
}


def collect(ctx):
    if ctx.sample_mode:
        return load_sample(ctx, "acsc")
    xml = get(ctx, FEED["url"]).text
    recs = rss_to_records("acsc", parse_rss(xml), rtype="advisory", severity="high", tags=["australia", "acsc"])
    for r in recs:
        t = r["title"].lower()
        if t.startswith("alert") or "critical" in t:
            r["severity"] = "critical"
    return recs