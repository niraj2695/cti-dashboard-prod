# Ethics and legal register

Signed off by the supervisor before any feed in the "sensitive" category goes live.

| feed | data category | what is retained | what is explicitly excluded | legal basis / terms | reviewed by | date |
|---|---|---|---|---|---|---|
| threatfox (infostealer families) | malware infrastructure | IOC, family, confidence | nothing from victims; no logs, no credentials | abuse.ch CC0 | | |
| ransomwarelive | extortion claims | group, victim name as posted publicly, country, sector, date | nothing from the leak itself, no links to leak sites, no downloaded data | ransomware.live terms | | |
| (future) hudson rock free API | infostealer exposure statistics | counts per domain, dates, family | usernames, emails, passwords, cookies, machine names | vendor free-tier terms | | |
| (future) HIBP breaches API | breach catalogue | breach name, date, record count, data classes | any per-account lookup | HIBP acceptable use | | |

## Standing rules

1. Metadata and aggregates only. If a field could identify a person or log them into something, it is not stored.
2. No sample downloads. Hashes and metadata only.
3. No interaction with attacker infrastructure: no visiting C2 hosts, no resolving leak-site onions.
4. Respect rate limits and set the project User-Agent.
5. When in doubt, exclude the data and ask the supervisor. Relevant law: Privacy Act 1988 (Cth), Criminal Code Act 1995 (Cth) Part 10.7.
