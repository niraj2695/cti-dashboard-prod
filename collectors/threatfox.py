"""abuse.ch ThreatFox: recent IOCs with malware family tags.

Requires a free abuse.ch Auth-Key (https://auth.abuse.ch/) in ABUSECH_API_KEY.
"""
from .base import get, load_sample, parse_date, post, record

FEED = {
    "id": "threatfox",
    "name": "abuse.ch ThreatFox",
    "category": "indicator",
    "url": "https://threatfox-api.abuse.ch/api/v1/",
    "licence": "CC0, attribution appreciated",
    "interval_minutes": 60,
}

STEALERS = {"lumma", "lummac2", "redline", "vidar", "stealc", "raccoon", "rhadamanthys",
            "meta stealer", "aurora", "risepro", "mystic", "atomic"}


def collect(ctx):
    if ctx.sample_mode:
        return load_sample(ctx, "threatfox")
    headers = {"Auth-Key": ctx.secret("ABUSECH_API_KEY") or ""}
    r = post(ctx, FEED["url"], json={"query": "get_iocs", "days": 1}, headers=headers)
    out = []
    for i in r.json().get("data", []) or []:
        fam = (i.get("malware_printable") or i.get("malware") or "unknown").strip()
        tags = [fam, i.get("ioc_type", ""), i.get("threat_type", "")]
        is_stealer = any(s in fam.lower() for s in STEALERS)
        if is_stealer:
            tags.append("infostealer")
        conf = int(i.get("confidence_level") or 0)
        out.append(record(
            feed="threatfox", rtype="indicator", rid=str(i["id"]),
            title=f'{i.get("ioc_type")}: {i.get("ioc")}',
            summary=f'{fam} ({i.get("threat_type_desc", "")}) confidence {conf}%',
            url=f'https://threatfox.abuse.ch/ioc/{i["id"]}/',
            published=parse_date(i.get("first_seen")),
            severity="high" if conf >= 75 else "medium",
            tags=[t for t in tags if t],
            extra={"ioc": i.get("ioc"), "ioc_type": i.get("ioc_type"), "malware": fam,
                   "threat_type": i.get("threat_type"), "confidence": conf,
                   "infostealer": is_stealer, "reporter": i.get("reporter")},
        ))
    return out
