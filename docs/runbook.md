# Runbook

## Is it healthy?
- Dashboard header dot: green all feeds ok, amber some failing, red most failing.
- `systemctl list-timers cti-*` shows next runs.
- `journalctl -u cti-collect -n 100` shows the last run.
- `curl -s https://<host>/data/meta.json | python3 -m json.tool` shows per-feed status and error text.

## A feed is red
1. Read `meta.json` error text. Common causes: expired or missing API key, source changed its URL or JSON shape, rate limited (429).
2. Reproduce: `sudo -u cti bash -c 'set -a; . /etc/cti/env; set +a; cd /srv/cti/app && .venv/bin/python -m pipeline.run --feeds <id>'`.
3. Fix in the collector, add or update the sample, run `pytest`, open a pull request. The other feeds keep running meanwhile.

## The whole pipeline is not running
- `systemctl status cti-collect.timer cti-collect.service`
- Disk full? `df -h /srv`. Clock drift? `timedatectl`.
- `sudo systemctl start cti-collect.service` to run once by hand.

## The page loads but shows nothing
- Browser console: a 404 on `/data/records.json` means Nginx alias or permissions (`ls -l /srv/cti/data`, must be readable by www-data: `chmod 755 /srv/cti/data`).
- A CSP error means a new external resource was added to the page; keep everything self-hosted.

## Host compromise suspected
1. Snapshot the EBS volume for evidence. 2. Remove the instance from the security group (deny all). 3. Rotate every key in `/etc/cti/env` and the GitHub deploy key. 4. Rebuild from `harden.sh` on a fresh instance; never clean in place. 5. Write it up as an incident in `docs/reports/`.

## Rebuild from scratch
See README "Server deployment". Total time about 30 minutes.
