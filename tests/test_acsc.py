from collectors import acsc
from collectors.base import Context


def test_collect_parses_cisa_rss(monkeypatch, tmp_path):
    class Response:
        text = """<?xml version="1.0"?>
        <rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/">
          <channel>
            <item>
              <title>#StopRansomware: Example Advisory</title>
              <link>https://www.cisa.gov/news-events/cybersecurity-advisories/example</link>
              <description>&lt;p&gt;Apply vendor updates.&lt;/p&gt;</description>
              <dc:date>2026-10-20T00:00:00Z</dc:date>
            </item>
          </channel>
        </rss>"""

    requested_urls = []

    def fake_get(ctx, url):
        requested_urls.append(url)
        return Response()

    monkeypatch.setattr(acsc, "get", fake_get)

    records = acsc.collect(Context(tmp_path))

    assert requested_urls == ["https://www.cisa.gov/cybersecurity-advisories/all.xml"]
    assert len(records) == 1
    assert records[0]["feed"] == "acsc"
    assert records[0]["type"] == "advisory"
    assert records[0]["title"] == "#StopRansomware: Example Advisory"
    assert records[0]["summary"] == "Apply vendor updates."
    assert records[0]["published"] == "2026-10-20T00:00:00Z"
    assert records[0]["severity"] == "info"
    assert records[0]["tags"] == ["cisa", "united-states"]
