"""Runs the whole pipeline in sample mode and checks the contract the dashboard relies on."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from collectors.base import parse_date, parse_rss, strip_html  # noqa: E402


@pytest.fixture(scope="session")
def data(tmp_path_factory):
    d = tmp_path_factory.mktemp("data")
    env = {**os.environ, "CTI_DATA_DIR": str(d)}
    subprocess.run([sys.executable, "-m", "pipeline.make_samples"], cwd=ROOT, check=True, capture_output=True)
    subprocess.run([sys.executable, "-m", "pipeline.run", "--sample"], cwd=ROOT, env=env, check=True, capture_output=True)
    return d


def test_outputs_exist(data):
    for f in ("records.json", "meta.json", "summary.json", "attack.json", "epss.json", "nvd.json"):
        assert (data / f).exists(), f


def test_records_follow_schema(data):
    recs = json.loads((data / "records.json").read_text())
    assert recs
    required = {"id", "type", "feed", "title", "summary", "url", "published", "severity", "tags", "extra", "first_seen"}
    for r in recs:
        assert required <= r.keys(), r
        assert r["type"] in {"vulnerability", "advisory", "indicator", "incident", "news", "technique"}
        assert r["severity"] in {"critical", "high", "medium", "low", "info", "unknown"}
        assert r["published"].endswith("Z")


def test_no_duplicates(data):
    recs = json.loads((data / "records.json").read_text())
    keys = [(r["feed"], r["id"]) for r in recs]
    assert len(keys) == len(set(keys))


def test_sorted_newest_first(data):
    recs = json.loads((data / "records.json").read_text())
    pubs = [r["published"] for r in recs]
    assert pubs == sorted(pubs, reverse=True)


def test_kev_enriched(data):
    recs = [r for r in json.loads((data / "records.json").read_text()) if r["feed"] == "kev"]
    assert all("epss" in r["extra"] and "cvss" in r["extra"] and "priority" in r["extra"] for r in recs)
    assert all(r["extra"]["priority"] >= 50 for r in recs)  # KEV floor


def test_infostealer_data_is_metadata_only(data):
    """Guard rail: nothing in an infostealer record may look like a credential."""
    recs = [r for r in json.loads((data / "records.json").read_text()) if r["extra"].get("infostealer")]
    for r in recs:
        blob = json.dumps(r).lower()
        for banned in ("password", "passwd", "cookie", "session_token", "@gmail.com"):
            assert banned not in blob, (banned, r["id"])


def test_meta_health(data):
    meta = json.loads((data / "meta.json").read_text())
    assert all(m["status"] == "ok" for m in meta.values())
    assert {"kev", "acsc", "threatfox", "urlhaus", "ransomwarelive", "news", "epss", "nvd", "attack"} <= meta.keys()


def test_rss_parser_rss2_and_atom():
    rss = """<rss><channel><item><title>A</title><link>https://x/a</link><pubDate>Mon, 13 Oct 2026 10:00:00 +0000</pubDate><description>&lt;p&gt;hi&lt;/p&gt;</description></item></channel></rss>"""
    atom = """<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>B</title><link href="https://x/b"/><updated>2026-10-13T10:00:00Z</updated><summary>s</summary></entry></feed>"""
    assert parse_rss(rss)[0]["link"] == "https://x/a"
    assert parse_rss(atom)[0]["link"] == "https://x/b"
    assert parse_date("Mon, 13 Oct 2026 10:00:00 +0000") == "2026-10-13T10:00:00Z"
    assert strip_html("<p>hi &amp; bye</p>") == "hi & bye"
