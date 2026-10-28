"""Generate the weekly threat landscape summary (Markdown) from data/records.json.

    python -m pipeline.weekly_report > docs/reports/$(date +%F).md
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import os
DATA = Path(os.environ.get("CTI_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))


def main():
    records = json.loads((DATA / "records.json").read_text())
    summary = json.loads((DATA / "summary.json").read_text())
    since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    week = [r for r in records if r["published"] >= since]

    def section(title, rows, fmt, limit=10):
        out = [f"\n## {title}\n"]
        if not rows:
            out.append("Nothing new this week.\n")
        for r in rows[:limit]:
            out.append(f"- {fmt(r)}")
        return "\n".join(out)

    kev = sorted([r for r in week if r["feed"] == "kev"], key=lambda r: -r["extra"].get("priority", 0))
    acsc = [r for r in week if r["feed"] == "acsc"]
    anz = [r for r in week if r["extra"].get("anz")]
    stealers = [r for r in week if r["extra"].get("infostealer")]
    news_au = [r for r in week if r["type"] == "news" and "australia" in r["tags"]]

    md = [
        f"# Weekly threat landscape summary",
        f"Generated {summary['generated']} covering the 7 days to {datetime.now(timezone.utc):%d %b %Y}.",
        f"\n**At a glance:** {summary['last_7d']['kev_added']} CVEs added to CISA KEV, "
        f"{summary['last_7d']['acsc']} CISA advisories, {summary['last_7d']['indicators']} new indicators "
        f"({summary['last_7d']['infostealer_iocs']} infostealer), {summary['last_7d']['ransomware_victims']} "
        f"ransomware victims posted ({summary['last_7d']['anz_victims']} in Australia or New Zealand).",
        section("Newly exploited vulnerabilities (CISA KEV), by priority", kev,
                lambda r: f"**{r['extra']['cve']}** {r['title'].split(' ', 1)[1]} "
                          f"(EPSS {r['extra'].get('epss', 'n/a')}, CVSS {r['extra'].get('cvss', 'n/a')}, "
                          f"patch by {r['extra'].get('due_date')}) {r['summary'][:140]}"),
        section("CISA cybersecurity advisories", acsc, lambda r: f"[{r['title']}]({r['url']})"),
        section("Ransomware victims in Australia and New Zealand", anz,
                lambda r: f"{r['extra']['group']} posted {r['extra']['victim']} ({r['extra'].get('sector') or 'sector unknown'})"),
        section("Top malware families by indicator volume", [{"k": k, "v": v} for k, v in summary["top_malware"]],
                lambda r: f"{r['k']}: {r['v']} indicators"),
        section("Most active ransomware groups", [{"k": k, "v": v} for k, v in summary["top_groups"]],
                lambda r: f"{r['k']}: {r['v']} victims"),
        section("Infostealer activity", stealers,
                lambda r: f"{r['extra']['malware']} {r['extra']['ioc_type']} ({r['extra'].get('threat_type')})", limit=8),
        section("Australian news", news_au, lambda r: f"[{r['title']}]({r['url']})"),
        "\n## Analyst assessment\n\n_(Written by the CTI Analyst each week: what changed, what it means for an Australian "
        "organisation, and what to do about it. The generated sections above are inputs, not the product.)_\n",
    ]
    print("\n".join(md))


if __name__ == "__main__":
    main()
