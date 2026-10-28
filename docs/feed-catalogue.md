# Feed catalogue

Verify every row in Week 1: open the URL, read the terms, record the date checked and your initials.

| id | source | format | tier | interval | key | licence / terms | fields retained | verified |
|---|---|---|---|---|---|---|---|---|
| kev | CISA KEV | JSON | 1 | 6h | no | US Gov, public domain | all catalogue fields | |
| nvd | NIST NVD 2.0 | JSON API | 1 | 24h | optional | public domain | CVSS, description | |
| epss | FIRST EPSS | JSON API | 1 | 24h | no | free with attribution | score, percentile | |
| acsc | CISA All Advisories | RSS | 1 | 1h | no | U.S. Government public information (verify source terms) | title, link, summary, date | |
| threatfox | abuse.ch ThreatFox | JSON API | 1 | 1h | yes | CC0 | ioc, type, family, confidence | |
| urlhaus | abuse.ch URLhaus | JSON API | 1 | 1h | yes | CC0 | url, host, status, threat | |
| ransomwarelive | ransomware.live | JSON API | 2 | 3h | no | non-commercial, attribution (confirm) | group, victim name as posted, country, sector, date | |
| news | 5 RSS wires | RSS | 1 | 1h | no | headlines and links only | title, link, summary, date | |
| attack | MITRE ATT&CK Enterprise | STIX 2.1 | 1 | 30d | no | MITRE terms of use | technique and group reference | |

## Candidates for Tier 2 and 3 (not yet implemented)

Feodo Tracker, MalwareBazaar, AlienVault OTX, OpenPhish, PhishTank, Spamhaus DROP, GreyNoise community,
AbuseIPDB, CERT NZ RSS, NCSC UK RSS, Hudson Rock free API (metadata only), HIBP breaches API,
MISP Galaxy threat actors, RansomWatch, itnews.com.au security RSS, Telegram public previews (vendor channels only).
