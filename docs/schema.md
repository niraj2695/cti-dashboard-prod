# Common record schema

Every collector returns records in this shape. The pipeline adds `first_seen` and enrichment fields.

| field | type | notes |
|---|---|---|
| id | string | unique within the feed: CVE id, ThreatFox id, URL hash, article link hash |
| type | string | vulnerability, advisory, indicator, incident, news, technique |
| feed | string | feed id, matches the collector module name |
| title | string | max 300 chars |
| summary | string | plain text, max ~400 chars, may be empty |
| url | string | link back to the source record |
| published | string | ISO 8601 UTC, `YYYY-MM-DDTHH:MM:SSZ` |
| severity | string | critical, high, medium, low, info, unknown |
| tags | list | free text: vendor, malware family, country, `anz`, `infostealer`, `ransomware`, news source |
| extra | object | feed-specific, see below |
| first_seen | string | added by pipeline: when this dashboard first saw the record |

## extra fields by type

- vulnerability: `cve`, `kev` (bool), `due_date`, `required_action`, `ransomware_use`, `cvss`, `cvss_severity`, `epss`, `epss_percentile`, `priority`
- indicator: `ioc`, `ioc_type`, `malware`, `threat_type`, `confidence`, `infostealer` (bool), `host`, `status`
- incident: `group`, `victim`, `country`, `sector`, `anz` (bool)
- news: `source`

## Retention

indicator 14 days, news 30, incident 90, advisory 180, vulnerability 365 (KEV entries are never pruned). Cap 5000 records.
