# CTI Dashboard: functional overview

## Purpose

The CTI Dashboard gives an organisation one place to review selected public cyber threat intelligence. It collects information from multiple threat feeds, presents it in a searchable visual dashboard, and provides a read-only AI assistant that can answer questions using the dashboard's current data.

The application is intended to help security teams and business stakeholders understand what has been reported, spot relevant changes sooner, and follow links to the original sources. It supports human decision-making; it does not make security decisions on behalf of an organisation.

## What the application does

- **Brings information together:** Collects vulnerability, advisory, malware-indicator, ransomware incident, threat group, and security-news records from configured public sources.
- **Makes records more consistent:** Converts different source formats into a shared record structure, removes duplicates, and retains source links and publication dates.
- **Adds useful context:** Enriches CVEs with available EPSS exploit-likelihood data, NVD CVSS severity information, and MITRE ATT&CK references. It calculates a prioritization score for vulnerability triage.
- **Shows activity at a glance:** Displays seven-day counts, feed health, last successful update times, and panels for key threat categories.
- **Supports exploration:** Allows users to search records by keyword and filter vulnerability data by severity.
- **Supports follow-up questions:** A bottom-right floating chat widget keeps named conversation threads in the user's browser so users can return to previous discussions and ask related follow-ups without leaving the dashboard. It can be opened or closed without covering dashboard content. Responses include source links and the data snapshot time. Threads remain on that browser and can be deleted.
- **Presents readable responses:** Headings, lists, emphasis, links, and code blocks are formatted for easier reading.
- **Looks up CVEs when explicitly asked:** A prompt in the exact form `Explain CVE-YYYY-NNNN` triggers a bounded lookup against NIST NVD. Other chat questions do not cause the assistant to browse the internet.
- **Produces a weekly summary:** A reporting utility generates a draft weekly threat landscape summary from the collected records for analyst review.
- **Highlights regional context:** Ransomware reporting and news panels surface Australia and New Zealand information where the source data provides it.

## Business advantages

| Advantage | Business value |
|---|---|
| Consolidated visibility | Reduces the need to check each supported feed separately and gives teams a shared starting point for situational awareness. |
| Faster triage | KEV, EPSS, CVSS, and ransomware context help analysts identify vulnerabilities that may warrant earlier review. The score is a prioritization aid, not a risk determination. |
| Clear data freshness | Feed status and timestamps make collection failures or stale information visible rather than implying all sources are current. |
| Traceable information | Records link back to their publishers so analysts can validate details and investigate further. |
| Easier access to context | The assistant can explain or summarize relevant records in natural language and includes sources for follow-up. |
| Lightweight deployment | The dashboard is a static web application backed by a scheduled Python pipeline; the chat API is a small separate service. It does not require a large application platform or database. |
| Improved privacy posture | The chat API authenticates to Azure OpenAI with the VM's managed identity, keeping model credentials off the user's browser. Infostealer data is treated as metadata only. |
| Flexible extension | The feed-based design and common schema allow maintainers to add sources without redesigning the dashboard data contract. |

## Typical use

1. A user opens the dashboard over HTTPS.
2. The user reviews summary tiles, feed health, and panels relevant to their role or current question.
3. The user searches or filters records, opens an original source, or asks the assistant a question about the current dashboard data.
4. An analyst validates important findings with the linked source and the organisation's own asset, exposure, and incident data before taking action.

The system has no user sign-in. Anyone who can reach the public site can use the chat feature, subject to HTTPS and server-side request limits.

## Information presented

Configured sources can include CISA KEV and advisories, NIST NVD, FIRST EPSS, abuse.ch ThreatFox and URLhaus, ransomware.live, TridentStack CVE data, MITRE ATT&CK, and security-news RSS feeds. Exact feed coverage and freshness depend on the deployed configuration and the upstream publishers.

The dashboard displays source metadata such as titles, descriptions, dates, severity, tags, CVE identifiers, malware families, indicators, incident details, and feed status. Data may be normalized, summarized, or enriched by the pipeline; source links are provided for verification.

## Important limitations

- Public feeds may be delayed, incomplete, changed, rate-limited, or temporarily unavailable. The dashboard can therefore be stale or incomplete.
- A feed reporting an issue does not establish that the organisation is affected. The application does not currently ingest the organisation's asset inventory or verify exposure.
- The vulnerability priority score is a triage aid, not a formal risk score, guarantee of exploitation, or substitute for business impact assessment.
- AI-generated answers can be incomplete or incorrect. Answers are limited to available dashboard context and should be checked against the cited source.
- The only external chat lookup is NIST NVD for an explicitly formatted `Explain CVE-...` request; it returns CVE metadata and not exploit instructions.
- The assistant does not browse arbitrary sites, execute code, create tickets, block indicators, patch systems, or perform incident response.
- Public chat can consume Azure OpenAI resources and incur costs. Server-side throttling reduces usage but does not replace cost monitoring and budget controls.
- The dashboard is not an alerting or monitoring guarantee. A missing record or unavailable feed must not be interpreted as evidence that no threat exists.

## Privacy and security

No dashboard login is required. The chat API is exposed through HTTPS and uses the VM's system-assigned managed identity for Azure OpenAI authentication. Azure credentials are kept on the server and are not sent to browser JavaScript. The API does not log the text of user questions.

Infostealer information is presented as metadata only. The project is designed not to store or display stolen credentials, cookies, session tokens, or personal identifiers. Users should avoid entering confidential or personal information into the public chat interface.

## Stakeholders and responsibilities

- **Business stakeholders** use dashboard findings as situational awareness and consult security staff for decisions.
- **Security analysts** validate information at the linked publisher, assess relevance to the organisation, and determine response priorities.
- **Platform maintainers** configure feed credentials, monitor collection and chat services, maintain TLS and Azure identity permissions, and review model and hosting costs.

For implementation and operational procedures, see `docs/technical-guide.md` and `docs/runbook.md`.
