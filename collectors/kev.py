"""CISA Known Exploited Vulnerabilities catalogue."""
from .base import get, load_sample, parse_date, record

FEED = {
    "id": "kev",
    "name": "CISA Known Exploited Vulnerabilities",
    "category": "vulnerability",
    "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "licence": "US Government work, public domain",
    "interval_minutes": 360,
}


def collect(ctx):
    if ctx.sample_mode:
        return load_sample(ctx, "kev")
    data = get(ctx, FEED["url"]).json()
    out = []
    for v in data.get("vulnerabilities", []):
        tags = [v.get("vendorProject", ""), v.get("product", "")]
        if v.get("knownRansomwareCampaignUse", "").lower() == "known":
            tags.append("ransomware")
        out.append(record(
            feed="kev", rtype="vulnerability", rid=v["cveID"],
            title=f'{v["cveID"]} {v.get("vendorProject", "")} {v.get("product", "")}'.strip(),
            summary=v.get("shortDescription", ""),
            url=f'https://www.cve.org/CVERecord?id={v["cveID"]}',
            published=parse_date(v.get("dateAdded")),
            severity="critical",  # exploited in the wild: always top of the queue
            tags=[t for t in tags if t],
            extra={
                "cve": v["cveID"],
                "kev": True,
                "due_date": v.get("dueDate"),
                "required_action": v.get("requiredAction"),
                "ransomware_use": v.get("knownRansomwareCampaignUse"),
                "cwes": v.get("cwes", []),
            },
        ))
    return out
