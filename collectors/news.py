"""Security news wires (RSS). Add or remove sources in SOURCES."""
from .base import get, load_sample, parse_rss, rss_to_records, log

FEED = {
    "id": "news",
    "name": "Security news wires",
    "category": "news",
    "url": "multiple",
    "licence": "Headlines and links only; full text is never stored",
    "interval_minutes": 60,
}

SOURCES = {
    "bleepingcomputer": "https://www.bleepingcomputer.com/feed/",
    "thehackernews": "https://feeds.feedburner.com/TheHackersNews",
    "therecord": "https://therecord.media/feed",
    "krebs": "https://krebsonsecurity.com/feed/",
    "securityweek": "https://www.securityweek.com/feed/",
}

KEYWORDS = {
    "ransomware": ["ransomware", "extortion", "leak site"],
    "infostealer": ["infostealer", "stealer", "lumma", "redline", "vidar"],
    "apt": ["apt", "nation-state", "state-sponsored", "espionage"],
    "vulnerability": ["cve-", "zero-day", "0-day", "patch", "vulnerability", "exploit"],
    "australia": ["australia", "australian", "acsc", "asd", "melbourne", "sydney", "nsw", "victoria"],
    "phishing": ["phishing", "credential", "mfa"],
    "cloud": ["aws", "azure", "cloud", "s3", "kubernetes"],
}


def _tag(text: str) -> list[str]:
    t = text.lower()
    return [k for k, words in KEYWORDS.items() if any(w in t for w in words)]


def collect(ctx):
    if ctx.sample_mode:
        return load_sample(ctx, "news")
    out = []
    for name, url in SOURCES.items():
        try:
            recs = rss_to_records("news", parse_rss(get(ctx, url).text), rtype="news", tags=[name])
        except Exception as e:  # one dead wire must not kill the others
            log.warning("news source %s failed: %s", name, e)
            continue
        for r in recs:
            r["tags"] = sorted(set(r["tags"] + _tag(r["title"] + " " + r["summary"])))
            r["extra"]["source"] = name
            if "australia" in r["tags"]:
                r["severity"] = "high"
        out.extend(recs)
    return out
