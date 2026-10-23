# Hardening checklist

Tick each item with evidence (command output or screenshot in docs/evidence/).

| # | control | CIS ref (Ubuntu 24.04) | how to verify | done |
|---|---|---|---|---|
| 1 | Automatic security updates | 1.9 | `cat /etc/apt/apt.conf.d/20auto-upgrades` | |
| 2 | SSH key-only, no root | 5.2 | `sshd -T \| grep -E 'permitrootlogin\|passwordauthentication'` | |
| 3 | SSH restricted to admin CIDRs | 3.5 | `ufw status numbered`; AWS security group | |
| 4 | Only 80/443 public | 3.5 | `ss -tlnp`; `nmap` from outside shows 22 filtered | |
| 5 | fail2ban active | n/a | `fail2ban-client status sshd` | |
| 6 | Service runs unprivileged, strict systemd sandbox | n/a | `systemd-analyze security cti-collect.service` | |
| 7 | Secrets outside the repo, mode 640 | n/a | `ls -l /etc/cti/env`; `git grep -i api_key` returns nothing | |
| 8 | TLS A grade | n/a | SSL Labs test | |
| 9 | Security headers present | n/a | `curl -I https://<host>` | |
| 10 | Login banner | 1.7 | `cat /etc/issue.net` | |
| 11 | sysctl network hardening | 3.3 | `sysctl net.ipv4.tcp_syncookies` | |
| 12 | Billing alert set in AWS | n/a | screenshot | |
| 13 | Backups: data/ synced to S3 daily | n/a | `aws s3 ls` | |
