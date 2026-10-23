"""
Shared helpers for all collectors.

Every collector module must define:
    FEED = {"id": "kev", "name": "CISA KEV", "category": "vulnerability",
            "url": "...", "licence": "...", "interval_minutes": 360}
    def collect(ctx) -> list[dict]   # returns records in the common schema

Common record schema (see docs/schema.md):
    {
      "id":        str   unique within the feed (CVE id, hash, URL, article link)
      "type":      str   vulnerability | advisory | indicator | incident | news | technique
      "feed":      str   feed id
      "title":     str
      "summary":   str   short, plain text, may be empty
      "url":       str   link back to the source
      "published": str   ISO 8601 UTC
      "severity":  str   critical | high | medium | low | info | unknown
      "tags":      list  free-form strings (malware family, vendor, country, ...)
      "extra":     dict  feed-specific fields (cve, cvss, epss, ioc, actor, ...)
    }
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html import unescape
from pathlib import Path
from typing import Callable

import requests

log = logging.getLogger("collectors")

USER_AGENT = os.environ.get(
    "CTI_USER_AGENT",
    "RMIT-Student-CTI-Dashboard/0.1 (+https://github.com/your-org/cti-dashboard; educational project)",
)
TIMEOUT = int(os.environ.get("CTI_HTTP_TIMEOUT", "30"))
RETRIES = 3


class Context:
    """Runtime context passed to every collector."""

    def __init__(self, data_dir: Path, sample_mode: bool = False):
        self.data_dir = data_dir
        self.sample_mode = sample_mode  # True = use bundled sample data, no network
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT

    def secret(self, name: str) -> str | None:
        """API keys come from the environment (loaded from /etc/cti/env on the server)."""
        return os.environ.get(name)


# ---------- HTTP ----------

def get(ctx: Context, url: str, *, before_request: Callable[[], None] | None = None,
        **kwargs) -> requests.Response:
    """GET with retry and backoff. Raises on final failure."""
    last = None
    for attempt in range(1, RETRIES + 1):
        try:
            if before_request:
                before_request()
            r = ctx.session.get(url, timeout=TIMEOUT, **kwargs)
            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", 2 ** attempt))
                log.warning("429 from %s, sleeping %ss", url, wait)
                time.sleep(wait)
                continue
            r.raise_for_status()
            return r
        except requests.RequestException as e:  # noqa: PERF203
            last = e
            log.warning("attempt %d failed for %s: %s", attempt, url, e)
            time.sleep(2 ** attempt)
    raise RuntimeError(f"GET failed after {RETRIES} attempts: {url}: {last}")


def post(ctx: Context, url: str, **kwargs) -> requests.Response:
    r = ctx.session.post(url, timeout=TIMEOUT, **kwargs)
    r.raise_for_status()
    return r


# ---------- dates ----------

def iso(dt: datetime | None) -> str:
    if dt is None:
        return now_iso()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_iso() -> str:
    return iso(datetime.now(timezone.utc))


def parse_date(value: str | None) -> str:
    """Best-effort parse of RFC 2822, ISO 8601 or YYYY-MM-DD into ISO UTC."""
    if not value:
        return now_iso()
    value = value.strip()
    try:
        return iso(parsedate_to_datetime(value))
    except (TypeError, ValueError):
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return iso(datetime.strptime(value.replace("Z", "+0000"), fmt))
        except ValueError:
            continue
    return now_iso()


# ---------- text ----------

TAG_RE = re.compile(r"<[^>]+>")


def strip_html(text: str | None, limit: int = 400) -> str:
    if not text:
        return ""
    text = unescape(TAG_RE.sub(" ", text))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit].rstrip() + ("..." if len(text) > limit else "")


def digest(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:16]


# ---------- RSS / Atom ----------

def parse_rss(xml_text: str) -> list[dict]:
    """Minimal RSS 2.0 / Atom parser. Returns dicts with title, link, summary, published."""
    items = []
    root = ET.fromstring(xml_text)
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    # RSS 2.0
    for it in root.iter("item"):
        items.append({
            "title": (it.findtext("title") or "").strip(),
            "link": (it.findtext("link") or "").strip(),
            "summary": it.findtext("description") or "",
            "published": it.findtext("pubDate") or it.findtext("{http://purl.org/dc/elements/1.1/}date"),
        })
    # Atom
    for en in root.findall(".//atom:entry", ns):
        link_el = en.find("atom:link", ns)
        items.append({
            "title": (en.findtext("atom:title", default="", namespaces=ns) or "").strip(),
            "link": link_el.get("href") if link_el is not None else "",
            "summary": en.findtext("atom:summary", default="", namespaces=ns)
                       or en.findtext("atom:content", default="", namespaces=ns),
            "published": en.findtext("atom:published", default=None, namespaces=ns)
                         or en.findtext("atom:updated", default=None, namespaces=ns),
        })
    return items


def rss_to_records(feed_id: str, items: list[dict], rtype: str = "news",
                   severity: str = "info", tags: list[str] | None = None) -> list[dict]:
    out = []
    for it in items:
        if not it.get("link"):
            continue
        out.append(record(
            feed=feed_id, rtype=rtype, rid=digest(it["link"]),
            title=it.get("title") or it["link"], summary=strip_html(it.get("summary")),
            url=it["link"], published=parse_date(it.get("published")),
            severity=severity, tags=list(tags or []), extra={},
        ))
    return out


# ---------- records ----------

def record(feed: str, rtype: str, rid: str, title: str, url: str, published: str,
           summary: str = "", severity: str = "unknown", tags: list[str] | None = None,
           extra: dict | None = None) -> dict:
    return {
        "id": rid, "type": rtype, "feed": feed, "title": title[:300],
        "summary": summary, "url": url, "published": published,
        "severity": severity, "tags": sorted(set(tags or [])), "extra": extra or {},
    }


def load_sample(ctx: Context, feed_id: str) -> list[dict]:
    """Bundled sample data lives in data/samples/<feed>.json for offline runs and tests."""
    path = Path(__file__).resolve().parent.parent / "data" / "samples" / f"{feed_id}.json"
    if not path.exists():
        return []
    return json.loads(path.read_text())
