"""abuse.ch URLhaus: recent malware distribution URLs (last 3 days, online only)."""
from .base import get, load_sample, parse_date, post, record

FEED = {
    "id": "urlhaus",
    "name": "abuse.ch URLhaus",
    "category": "indicator",
    "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
    "licence": "CC0, attribution appreciated",
    "interval_minutes": 60,
}


def collect(ctx):
    if ctx.sample_mode:
        return load_sample(ctx, "urlhaus")
    headers = {"Auth-Key": ctx.secret("ABUSECH_API_KEY") or ""}
    r = get(ctx, FEED["url"], headers=headers)
    out = []
    for u in r.json().get("urls", []) or []:
        tags = list(u.get("tags") or []) + [u.get("threat", "")]
        out.append(record(
            feed="urlhaus", rtype="indicator", rid=str(u["id"]),
            title=f'URL: {u.get("host")}',
            summary=f'{u.get("threat")} {" ".join(u.get("tags") or [])} status {u.get("url_status")}',
            url=u.get("urlhaus_reference", ""),
            published=parse_date(u.get("date_added")),
            severity="high" if u.get("url_status") == "online" else "medium",
            tags=[t for t in tags if t],
            extra={"ioc": u.get("url"), "ioc_type": "url", "host": u.get("host"),
                   "status": u.get("url_status"), "threat": u.get("threat")},
        ))
    return out
