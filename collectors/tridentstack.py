"""TridentStack CVE catalogue integration.

This source exposes search/list CVEs via a paginated API. Results are mapped to the
common vulnerability schema so they appear alongside KEV entries in the exploited
vulnerabilities panel.
"""
from __future__ import annotations

import json
import logging
import time

from .base import get, load_sample, parse_date, record

log = logging.getLogger("collectors")
REQUEST_LIMIT = 50
REQUEST_WINDOW_SECONDS = 60 * 60
STATE_FILE = "tridentstack_state.json"

FEED = {
    "id": "tridentstack",
    "name": "TridentStack CVE",
    "category": "vulnerability",
    "url": "https://tridentstack.com/api/v1/cve",
    "licence": "TridentStack public API",
    "interval_minutes": 60,
}

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFORMATIONAL": "info",
}


def collect(ctx):
    if ctx.sample_mode:
        return load_sample(ctx, "tridentstack")

    state_path = ctx.data_dir / STATE_FILE
    try:
        state = json.loads(state_path.read_text()) if state_path.exists() else {}
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read TridentStack pagination state: {exc}") from exc
    if not isinstance(state, dict):
        raise RuntimeError(f"Invalid TridentStack pagination state in {state_path}")

    timestamps = state.get("request_timestamps", [])
    if not isinstance(timestamps, list) or any(not isinstance(ts, (int, float)) for ts in timestamps):
        raise RuntimeError(f"Invalid TridentStack request history in {state_path}")
    now = time.time()
    timestamps = [ts for ts in timestamps if now - ts < REQUEST_WINDOW_SECONDS]
    cursor = state.get("cursor")
    if cursor is not None and not isinstance(cursor, str):
        raise RuntimeError(f"Invalid TridentStack pagination cursor in {state_path}")

    def save_state(next_cursor):
        state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = state_path.with_suffix(".tmp")
        temporary_path.write_text(json.dumps({
            "request_timestamps": timestamps,
            "cursor": next_cursor,
        }))
        temporary_path.replace(state_path)

    class RequestLimitReached(Exception):
        pass

    def record_request():
        if len(timestamps) >= REQUEST_LIMIT:
            raise RequestLimitReached
        timestamps.append(time.time())
        save_state(cursor)

    out = []
    while True:
        params = {"limit": 30}
        if cursor:
            params["nextCursor"] = cursor
        try:
            data = get(ctx, FEED["url"], params=params, before_request=record_request).json()
        except RequestLimitReached:
            log.warning("TridentStack hourly request limit reached; pagination will resume next run")
            break

        for item in data.get("results", []):
            cve = item.get("cveId")
            if not cve:
                continue
            sev = (item.get("severity") or "UNKNOWN").upper()
            tags = ["tridentstack", "cve"]
            if item.get("isKev"):
                tags.append("kev")
            if item.get("hasRemediation"):
                tags.append("fix")
            out.append(record(
                feed="tridentstack",
                rtype="vulnerability",
                rid=cve,
                title=f"{cve} TridentStack CVE",
                summary=f"TridentStack CVE entry for {cve}.",
                url=f"https://tridentstack.com/api/v1/cve/{cve}",
                published=parse_date(item.get("publishedAt")),
                severity=SEVERITY_MAP.get(sev, "unknown"),
                tags=tags,
                extra={
                    "cve": cve,
                    "kev": bool(item.get("isKev")),
                    "fix": bool(item.get("hasRemediation")),
                    "cvss": item.get("cvss"),
                    "epss": item.get("epss"),
                    "source": "tridentstack",
                    "source_type": "api",
                    "published_at": item.get("publishedAt"),
                },
            ))

        next_cursor = data.get("nextCursor")
        cursor = next_cursor
        save_state(cursor)
        if not next_cursor:
            break
    return out
