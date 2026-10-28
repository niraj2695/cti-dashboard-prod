"""CISA all-advisories RSS collector.

The legacy ``acsc`` feed id is retained for compatibility with existing data and UI.
"""
from .base import get, load_sample, parse_rss, rss_to_records

FEED = {
    "id": "acsc",
    "name": "CISA All Advisories",
    "category": "advisory",
    "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "licence": "U.S. Government public information; verify source terms",
    "interval_minutes": 60,
}


def collect(ctx):
    if ctx.sample_mode:
        return load_sample(ctx, "acsc")
    xml = get(ctx, FEED["url"]).text
    return rss_to_records(
        "acsc",
        parse_rss(xml),
        rtype="advisory",
        severity="info",
        tags=["cisa", "united-states"],
    )
