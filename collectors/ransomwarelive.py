"""ransomware.live: recent leak-site victim postings. Filtered to AU/NZ plus a global sample.

Only metadata is kept (group, victim organisation name as posted, country, date, sector).
Nothing from the leak itself is ever fetched.
"""
from .base import get, load_sample, parse_date, record

FEED = {
    "id": "ransomwarelive",
    "name": "ransomware.live",
    "category": "incident",
    "url": "https://api.ransomware.live/v2/recentvictims",
    "licence": "Free for non-commercial use, attribution required (verify current terms)",
    "interval_minutes": 180,
}

FOCUS = {"AU", "NZ", "Australia", "New Zealand"}


def collect(ctx):
    if ctx.sample_mode:
        return load_sample(ctx, "ransomwarelive")
    r = get(ctx, FEED["url"])
    rows = r.json() if isinstance(r.json(), list) else r.json().get("data", [])
    out = []
    for v in rows:
        country = (v.get("country") or "").strip()
        focus = country in FOCUS
        tags = [v.get("group") or v.get("group_name") or "unknown", country or "unknown", v.get("activity") or v.get("sector") or ""]
        if focus:
            tags.append("anz")
        out.append(record(
            feed="ransomwarelive", rtype="incident",
            rid=f'{v.get("group") or v.get("group_name")}:{v.get("victim") or v.get("post_title")}',
            title=f'{(v.get("group") or v.get("group_name") or "?")} claims {(v.get("victim") or v.get("post_title") or "?")}',
            summary=(v.get("description") or "")[:300],
            url=v.get("url") or v.get("website") or "https://www.ransomware.live/",
            published=parse_date(v.get("discovered") or v.get("published") or v.get("attackdate")),
            severity="critical" if focus else "medium",
            tags=[t for t in tags if t],
            extra={"group": v.get("group") or v.get("group_name"), "victim": v.get("victim") or v.get("post_title"),
                   "country": country, "sector": v.get("activity") or v.get("sector"), "anz": focus},
        ))
    return out
