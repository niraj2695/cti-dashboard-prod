"""Write illustrative sample data to data/samples/ so the pipeline and dashboard run offline.

SAMPLE DATA IS ILLUSTRATIVE. CVE ids, hosts and victim names here are invented or historical
and must not be treated as current intelligence. Run the real collectors on the server.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from collectors.base import digest, iso, record

OUT = Path(__file__).resolve().parent.parent / "data" / "samples"
random.seed(7)
NOW = datetime.now(timezone.utc)


def ago(hours: float) -> str:
    return iso(NOW - timedelta(hours=hours))


def dump(name, obj):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{name}.json").write_text(json.dumps(obj, indent=1))


# KEV
kev_rows = [
    ("CVE-2026-31337", "Fortinet", "FortiOS", "Authentication bypass in the SSL-VPN web interface allows unauthenticated remote code execution.", "Known"),
    ("CVE-2026-28810", "Microsoft", "Windows", "Elevation of privilege in the Common Log File System driver.", "Known"),
    ("CVE-2026-27402", "Ivanti", "Connect Secure", "Stack buffer overflow permitting remote code execution.", "Unknown"),
    ("CVE-2026-26215", "Cisco", "IOS XE", "Web UI privilege escalation via crafted requests.", "Unknown"),
    ("CVE-2026-25109", "Atlassian", "Confluence", "Server-side template injection leading to RCE.", "Known"),
    ("CVE-2026-24077", "Palo Alto Networks", "PAN-OS", "Command injection in GlobalProtect.", "Unknown"),
    ("CVE-2026-23930", "Citrix", "NetScaler ADC", "Memory overread exposing session tokens.", "Known"),
    ("CVE-2026-22814", "Apple", "iOS", "WebKit type confusion exploited in targeted attacks.", "Unknown"),
    ("CVE-2025-61921", "Oracle", "E-Business Suite", "Unauthenticated access to sensitive data.", "Known"),
    ("CVE-2025-59287", "Microsoft", "WSUS", "Deserialisation of untrusted data leading to RCE.", "Unknown"),
    ("CVE-2025-55182", "Progress", "MOVEit Transfer", "SQL injection in the web application.", "Known"),
    ("CVE-2025-53770", "Microsoft", "SharePoint Server", "Deserialisation permitting unauthenticated RCE.", "Known"),
]
kev = []
for i, (cve, vendor, product, desc, rw) in enumerate(kev_rows):
    tags = [vendor, product] + (["ransomware"] if rw == "Known" else [])
    kev.append(record("kev", "vulnerability", cve, f"{cve} {vendor} {product}", f"https://www.cve.org/CVERecord?id={cve}",
                      ago(6 + i * 30), summary=desc, severity="critical", tags=tags,
                      extra={"cve": cve, "kev": True, "due_date": (NOW + timedelta(days=21 - i)).strftime("%Y-%m-%d"),
                             "required_action": "Apply mitigations per vendor instructions or discontinue use.",
                             "ransomware_use": rw, "cwes": []}))
dump("kev", kev)

# EPSS and NVD enrichment tables
dump("epss", [{"cve": c, "epss": round(random.uniform(0.05, 0.97), 4), "percentile": round(random.uniform(0.6, 0.999), 4),
               "date": NOW.strftime("%Y-%m-%d")} for c, *_ in kev_rows])
dump("nvd", [{"cve": c, "cvss": random.choice([7.5, 8.1, 8.8, 9.1, 9.8, 10.0]), "cvss_severity": random.choice(["high", "critical"]),
              "cvss_version": "cvssMetricV31", "description": d} for c, v, p, d, _ in kev_rows])

# CISA Cybersecurity Advisories
cisa_titles = [
    "CISA Cybersecurity Advisory: Ransomware activity targeting critical infrastructure",
    "CISA Cybersecurity Advisory: Actively exploited vulnerability in edge devices",
    "CISA Cybersecurity Advisory: Guidance for securing cloud environments",
    "CISA Cybersecurity Advisory: Threat actor techniques and mitigations",
    "CISA Cybersecurity Advisory: Malware indicators and defensive actions",
    "CISA Cybersecurity Advisory: Protecting organizations from phishing",
]
dump("acsc", [record("acsc", "advisory", digest(t), t, f"https://www.cisa.gov/news-events/cybersecurity-advisories/{digest(t)}",
                     ago(3 + i * 26), summary="Summary text from the CISA advisory would appear here.", severity="info",
                     tags=["cisa", "united-states"]) for i, t in enumerate(cisa_titles)])

# ThreatFox
fams = ["Lumma Stealer", "RedLine Stealer", "Vidar", "StealC", "Cobalt Strike", "AsyncRAT", "Remcos", "QakBot", "Rhadamanthys", "XWorm"]
stealers = {"Lumma Stealer", "RedLine Stealer", "Vidar", "StealC", "Rhadamanthys"}
tf = []
for i in range(60):
    fam = random.choice(fams)
    ioc_type = random.choice(["ip:port", "domain", "url", "sha256_hash"])
    ioc = {"ip:port": f"{random.randint(5,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}:{random.choice([443,8080,4444,2404])}",
           "domain": f"{random.choice(['update','cdn','api','secure','login'])}-{random.randint(100,999)}.{random.choice(['top','xyz','shop','icu'])}",
           "url": f"https://files-{random.randint(10,99)}.{random.choice(['top','xyz'])}/{random.choice(['setup','update','invoice'])}.exe",
           "sha256_hash": digest(str(i)) * 4}[ioc_type]
    conf = random.choice([50, 75, 90, 100])
    tf.append(record("threatfox", "indicator", str(1300000 + i), f"{ioc_type}: {ioc}", f"https://threatfox.abuse.ch/ioc/{1300000+i}/",
                     ago(random.uniform(0.5, 160)), summary=f"{fam} (botnet C2) confidence {conf}%",
                     severity="high" if conf >= 75 else "medium",
                     tags=[fam, ioc_type, "botnet_cc"] + (["infostealer"] if fam in stealers else []),
                     extra={"ioc": ioc, "ioc_type": ioc_type, "malware": fam, "threat_type": "botnet_cc",
                            "confidence": conf, "infostealer": fam in stealers, "reporter": "abuse_ch"}))
dump("threatfox", tf)

# URLhaus
uh = []
for i in range(40):
    host = f"{random.choice(['dl','get','cdn','mirror'])}{random.randint(1,99)}.{random.choice(['example-host.top','files-store.xyz','drop-zone.icu'])}"
    status = random.choice(["online", "online", "offline"])
    uh.append(record("urlhaus", "indicator", str(3400000 + i), f"URL: {host}", f"https://urlhaus.abuse.ch/url/{3400000+i}/",
                     ago(random.uniform(1, 70)), summary=f"malware_download exe status {status}",
                     severity="high" if status == "online" else "medium", tags=["malware_download", "exe", random.choice(["Lumma Stealer", "Remcos", "Amadey"])],
                     extra={"ioc": f"https://{host}/{random.choice(['inv','doc','setup'])}.exe", "ioc_type": "url", "host": host,
                            "status": status, "threat": "malware_download"}))
dump("urlhaus", uh)

# ransomware.live
groups = ["qilin", "akira", "play", "lynx", "safepay", "incransom", "medusa", "clop"]
victims = [("Example Logistics Pty Ltd", "AU", "Transport"), ("Harbourview Medical Group", "AU", "Healthcare"),
           ("Northfield Engineering", "NZ", "Manufacturing"), ("Metro Legal Partners", "AU", "Legal"),
           ("Acme Retail Corp", "US", "Retail"), ("Nordic Shipping AS", "NO", "Transport"),
           ("Bavarian Auto Parts GmbH", "DE", "Manufacturing"), ("Riverside School District", "US", "Education"),
           ("Pacific Mining Services", "AU", "Mining"), ("Coastal Credit Union", "US", "Finance"),
           ("Lakeside Hospital Trust", "GB", "Healthcare"), ("Southern Cross Agri Co-op", "NZ", "Agriculture")]
rl = []
for i, (v, c, s) in enumerate(victims):
    g = random.choice(groups)
    anz = c in {"AU", "NZ"}
    rl.append(record("ransomwarelive", "incident", f"{g}:{v}", f"{g} claims {v}", "https://www.ransomware.live/",
                     ago(random.uniform(2, 150)), summary="", severity="critical" if anz else "medium",
                     tags=[g, c, s] + (["anz"] if anz else []),
                     extra={"group": g, "victim": v, "country": c, "sector": s, "anz": anz}))
dump("ransomwarelive", rl)

# News
headlines = [
    ("bleepingcomputer", "Fortinet warns of actively exploited SSL-VPN zero-day", ["vulnerability"]),
    ("thehackernews", "Lumma Stealer resurfaces with new loader targeting enterprise users", ["infostealer"]),
    ("therecord", "Australian logistics firm confirms ransomware attack disrupting deliveries", ["ransomware", "australia"]),
    ("krebs", "Inside the infostealer log economy", ["infostealer"]),
    ("securityweek", "Cisco patches IOS XE flaw exploited by state-backed group", ["vulnerability", "apt"]),
    ("bleepingcomputer", "Qilin ransomware claims attack on New Zealand manufacturer", ["ransomware"]),
    ("thehackernews", "Phishing campaign abuses myGov branding to harvest credentials", ["phishing", "australia"]),
    ("therecord", "ACSC publishes annual Cyber Threat Report", ["australia"]),
    ("securityweek", "AWS IAM misconfiguration leads to data exposure at SaaS provider", ["cloud"]),
    ("bleepingcomputer", "Microsoft WSUS RCE now exploited in the wild", ["vulnerability"]),
    ("krebs", "Who is behind the Scattered Spider arrests?", ["apt"]),
    ("thehackernews", "Chinese APT targets Australian telecoms with new backdoor", ["apt", "australia"]),
]
dump("news", [record("news", "news", digest(t), t, f"https://example.invalid/{digest(t)}", ago(1 + i * 11),
                     summary="Article summary would appear here.", severity="high" if "australia" in tg else "info",
                     tags=[src] + tg, extra={"source": src}) for i, (src, t, tg) in enumerate(headlines)])

# ATT&CK reference (tiny subset)
dump("attack", [{
    "techniques": {
        "T1566": {"name": "Phishing", "tactics": ["initial-access"], "url": "https://attack.mitre.org/techniques/T1566/"},
        "T1190": {"name": "Exploit Public-Facing Application", "tactics": ["initial-access"], "url": "https://attack.mitre.org/techniques/T1190/"},
        "T1059": {"name": "Command and Scripting Interpreter", "tactics": ["execution"], "url": "https://attack.mitre.org/techniques/T1059/"},
        "T1486": {"name": "Data Encrypted for Impact", "tactics": ["impact"], "url": "https://attack.mitre.org/techniques/T1486/"},
        "T1555": {"name": "Credentials from Password Stores", "tactics": ["credential-access"], "url": "https://attack.mitre.org/techniques/T1555/"},
        "T1071": {"name": "Application Layer Protocol", "tactics": ["command-and-control"], "url": "https://attack.mitre.org/techniques/T1071/"},
    },
    "groups": {
        "G0016": {"name": "APT29", "aliases": ["Cozy Bear", "Midnight Blizzard", "NOBELIUM"], "techniques": ["T1566", "T1059", "T1071"], "url": "https://attack.mitre.org/groups/G0016/"},
        "G1015": {"name": "Scattered Spider", "aliases": ["Octo Tempest", "UNC3944"], "techniques": ["T1566", "T1555", "T1486"], "url": "https://attack.mitre.org/groups/G1015/"},
        "G0032": {"name": "Lazarus Group", "aliases": ["HIDDEN COBRA", "Diamond Sleet"], "techniques": ["T1190", "T1059", "T1071"], "url": "https://attack.mitre.org/groups/G0032/"},
    },
}])
print("samples written to", OUT)
