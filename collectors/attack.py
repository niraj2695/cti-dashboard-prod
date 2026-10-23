"""MITRE ATT&CK Enterprise STIX bundle: technique and group reference data.

Large (tens of MB); refreshed monthly. Produces reference tables rather than records:
    techniques: {T1059: {name, tactics, url}}
    groups:     {G0016: {name, aliases, techniques: [..], url}}
"""
from .base import get, load_sample

FEED = {
    "id": "attack",
    "name": "MITRE ATT&CK Enterprise",
    "category": "reference",
    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "licence": "MITRE, Apache 2.0 style terms of use",
    "interval_minutes": 43200,
}


def collect(ctx):
    return []


def reference_tables(ctx) -> dict:
    if ctx.sample_mode:
        return load_sample(ctx, "attack")[0]
    bundle = get(ctx, FEED["url"]).json()
    objs = bundle.get("objects", [])
    techniques, groups, by_id = {}, {}, {}
    for o in objs:
        ext = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ext or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        by_id[o["id"]] = ext["external_id"]
        if o["type"] == "attack-pattern":
            techniques[ext["external_id"]] = {
                "name": o["name"],
                "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])],
                "url": ext.get("url"),
            }
        elif o["type"] == "intrusion-set":
            groups[ext["external_id"]] = {"name": o["name"], "aliases": o.get("aliases", []),
                                          "techniques": [], "url": ext.get("url")}
    for o in objs:
        if o["type"] == "relationship" and o.get("relationship_type") == "uses":
            src, tgt = by_id.get(o["source_ref"]), by_id.get(o["target_ref"])
            if src in groups and tgt in techniques:
                groups[src]["techniques"].append(tgt)
    return {"techniques": techniques, "groups": groups}
