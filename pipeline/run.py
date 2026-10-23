"""
Pipeline entry point.

    python -m pipeline.run                 # run all feeds that are due
    python -m pipeline.run --feeds kev acsc  # run specific feeds now
    python -m pipeline.run --all           # ignore intervals, run everything
    python -m pipeline.run --sample        # offline: use data/samples, no network

Outputs (all under data/):
    records.json      merged, deduplicated, enriched records (newest first)
    meta.json         per-feed health: last run, status, record count, error
    attack.json       ATT&CK reference tables
    summary.json      counts the dashboard uses for its stat tiles
"""
from __future__ import annotations

import argparse
import importlib
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from collectors.base import Context, now_iso

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.environ.get("CTI_DATA_DIR", ROOT / "data"))

RECORD_FEEDS = ["kev", "tridentstack", "acsc", "threatfox", "urlhaus", "ransomwarelive", "news"]
ENRICH_FEEDS = ["epss", "nvd", "attack"]
RETENTION_DAYS = {"indicator": 14, "news": 30, "incident": 90, "advisory": 180, "vulnerability": 365}
MAX_RECORDS = 5000

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("pipeline")


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=1, ensure_ascii=False))
    tmp.replace(path)  # atomic: the dashboard never reads a half-written file


def due(meta: dict, feed: dict, force: bool) -> bool:
    if force:
        return True
    last = meta.get(feed["id"], {}).get("last_success")
    if not last:
        return True
    last_dt = datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - last_dt >= timedelta(minutes=feed["interval_minutes"])


def validate(rec: dict) -> bool:
    required = {"id", "type", "feed", "title", "url", "published", "severity", "tags", "extra"}
    return required <= rec.keys() and bool(rec["id"]) and bool(rec["title"])


def merge(existing: list[dict], fresh: list[dict], feed_id: str) -> list[dict]:
    """Dedup on (feed, id). Fresh records replace old ones; untouched old ones are kept."""
    by_key = {(r["feed"], r["id"]): r for r in existing}
    for r in fresh:
        if validate(r):
            key = (r["feed"], r["id"])
            if key in by_key:
                r["first_seen"] = by_key[key].get("first_seen", r["published"])
            else:
                r["first_seen"] = now_iso()
            by_key[key] = r
        else:
            log.warning("dropped invalid record from %s: %s", feed_id, r.get("id"))
    return list(by_key.values())


def prune(records: list[dict]) -> list[dict]:
    now = datetime.now(timezone.utc)
    kept = []
    for r in records:
        days = RETENTION_DAYS.get(r["type"], 30)
        pub = datetime.strptime(r["published"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        if now - pub <= timedelta(days=days) or r["extra"].get("kev"):
            kept.append(r)
    kept.sort(key=lambda r: r["published"], reverse=True)
    return kept[:MAX_RECORDS]


def enrich(ctx: Context, records: list[dict], meta: dict, force: bool) -> dict:
    """EPSS and CVSS on every record that carries a CVE; ATT&CK tables refreshed monthly."""
    from collectors import epss, nvd, attack

    cves = sorted({r["extra"]["cve"] for r in records if r["extra"].get("cve")})
    epss_t = load_json(DATA / "epss.json", {})
    nvd_t = load_json(DATA / "nvd.json", {})
    attack_t = load_json(DATA / "attack.json", {"techniques": {}, "groups": {}})

    for mod, name, table in ((epss, "epss", epss_t), (nvd, "nvd", nvd_t)):
        if due(meta, mod.FEED, force):
            try:
                table.update(mod.enrich_table(ctx, cves, table) if name == "nvd" else mod.enrich_table(ctx, cves))
                save_json(DATA / f"{name}.json", table)
                meta[name] = {"name": mod.FEED["name"], "category": "enrichment", "interval_minutes": mod.FEED["interval_minutes"],
                              "last_run": now_iso(), "last_success": now_iso(), "status": "ok", "count": len(table), "error": None}
            except Exception as e:
                log.exception("%s enrichment failed", name)
                meta[name] = {**meta.get(name, {}), "name": mod.FEED["name"], "last_run": now_iso(),
                              "status": "error", "error": str(e)[:300]}

    if due(meta, attack.FEED, force) or not attack_t["techniques"]:
        try:
            attack_t = attack.reference_tables(ctx)
            save_json(DATA / "attack.json", attack_t)
            meta["attack"] = {"name": attack.FEED["name"], "category": "reference", "interval_minutes": attack.FEED["interval_minutes"],
                              "last_run": now_iso(), "last_success": now_iso(), "status": "ok", "count": len(attack_t["techniques"]), "error": None}
        except Exception as e:
            log.exception("attack refresh failed")
            meta["attack"] = {**meta.get("attack", {}), "name": attack.FEED["name"], "last_run": now_iso(),
                              "status": "error", "error": str(e)[:300]}

    for r in records:
        cve = r["extra"].get("cve")
        if not cve:
            continue
        if cve in epss_t:
            r["extra"]["epss"] = epss_t[cve]["epss"]
            r["extra"]["epss_percentile"] = epss_t[cve]["percentile"]
        if cve in nvd_t:
            r["extra"]["cvss"] = nvd_t[cve].get("cvss")
            r["extra"]["cvss_severity"] = nvd_t[cve].get("cvss_severity")
            if not r["summary"] and nvd_t[cve].get("description"):
                r["summary"] = nvd_t[cve]["description"]
        # Priority score: KEV beats everything, then EPSS, then CVSS. Students refine this in Week 4.
        score = 0.0
        if r["extra"].get("kev"):
            score += 50
        score += 40 * float(r["extra"].get("epss") or 0)
        score += float(r["extra"].get("cvss") or 0)
        if "ransomware" in r["tags"]:
            score += 10
        r["extra"]["priority"] = round(score, 1)
    return attack_t


def summarise(records: list[dict], attack_t: dict, meta: dict) -> dict:
    week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    recent = [r for r in records if r["published"] >= week_ago]
    by_type = {}
    for r in records:
        by_type[r["type"]] = by_type.get(r["type"], 0) + 1
    families = {}
    for r in records:
        if r["type"] == "indicator" and r["extra"].get("malware"):
            families[r["extra"]["malware"]] = families.get(r["extra"]["malware"], 0) + 1
    groups = {}
    for r in records:
        if r["type"] == "incident" and r["extra"].get("group"):
            groups[r["extra"]["group"]] = groups.get(r["extra"]["group"], 0) + 1
    return {
        "generated": now_iso(),
        "totals": by_type,
        "last_7d": {"kev_added": sum(1 for r in recent if r["feed"] == "kev"),
                    "acsc": sum(1 for r in recent if r["feed"] == "acsc"),
                    "indicators": sum(1 for r in recent if r["type"] == "indicator"),
                    "infostealer_iocs": sum(1 for r in recent if r["extra"].get("infostealer")),
                    "ransomware_victims": sum(1 for r in recent if r["type"] == "incident"),
                    "anz_victims": sum(1 for r in recent if r["extra"].get("anz")),
                    "news": sum(1 for r in recent if r["type"] == "news")},
        "top_malware": sorted(families.items(), key=lambda kv: -kv[1])[:10],
        "top_groups": sorted(groups.items(), key=lambda kv: -kv[1])[:10],
        "attack_techniques": len(attack_t.get("techniques", {})),
        "attack_groups": len(attack_t.get("groups", {})),
        "feeds_ok": sum(1 for m in meta.values() if m.get("status") == "ok"),
        "feeds_total": len(meta),
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--feeds", nargs="*", help="feed ids to run now")
    ap.add_argument("--all", action="store_true", help="run every feed regardless of interval")
    ap.add_argument("--sample", action="store_true", help="offline mode using data/samples")
    args = ap.parse_args(argv)

    ctx = Context(DATA, sample_mode=args.sample)
    meta = load_json(DATA / "meta.json", {})
    records = load_json(DATA / "records.json", [])
    force_all = args.all or args.sample
    selected = args.feeds or RECORD_FEEDS

    for fid in selected:
        mod = importlib.import_module(f"collectors.{fid}")
        feed = mod.FEED
        if not (args.feeds or due(meta, feed, force_all)):
            log.info("%s not due, skipping", fid)
            continue
        entry = {**meta.get(fid, {}), "name": feed["name"], "category": feed["category"],
                 "licence": feed["licence"], "interval_minutes": feed["interval_minutes"],
                 "last_run": now_iso()}
        try:
            fresh = mod.collect(ctx)
            records = merge([r for r in records if r["feed"] != fid] + [r for r in records if r["feed"] == fid], fresh, fid)
            entry.update(status="ok", last_success=now_iso(), error=None,
                         count=sum(1 for r in records if r["feed"] == fid), fetched=len(fresh))
            log.info("%s: %d fetched", fid, len(fresh))
        except Exception as e:
            log.exception("%s failed", fid)
            entry.update(status="error", error=str(e)[:300])
        meta[fid] = entry

    records = prune(records)
    attack_t = enrich(ctx, records, meta, force_all)
    records.sort(key=lambda r: r["published"], reverse=True)
    save_json(DATA / "records.json", records)
    save_json(DATA / "meta.json", meta)
    save_json(DATA / "summary.json", summarise(records, attack_t, meta))
    log.info("done: %d records, %d feeds ok", len(records),
             sum(1 for m in meta.values() if m.get("status") == "ok"))
    return 0 if all(m.get("status") == "ok" for m in meta.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
