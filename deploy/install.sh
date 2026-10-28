#!/usr/bin/env bash
# Install or update the application on the server. Run from the repository root as a sudo user:
#   sudo bash deploy/install.sh
# Idempotent: safe to re-run on every deploy (the GitHub Actions workflow does exactly this).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
APP=/srv/cti/app

echo "[1/5] sync application code"
install -d -o cti -g cti /srv/cti
rsync -a --delete --exclude .git --exclude data --exclude .github "$REPO/" "$APP/"
chown -R cti:cti "$APP"

echo "[2/5] python virtualenv"
sudo -u cti python3 -m venv "$APP/.venv"
sudo -u cti "$APP/.venv/bin/pip" install -q --upgrade pip
sudo -u cti "$APP/.venv/bin/pip" install -q -r "$APP/requirements.txt"

echo "[3/5] systemd units"
install -m 644 "$APP/deploy/cti-collect.service" /etc/systemd/system/
install -m 644 "$APP/deploy/cti-collect.timer"   /etc/systemd/system/
install -m 644 "$APP/deploy/cti-report.service"  /etc/systemd/system/
install -m 644 "$APP/deploy/cti-report.timer"    /etc/systemd/system/
install -m 644 "$APP/deploy/cti-chat.service"    /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now cti-collect.timer cti-report.timer
systemctl enable --now cti-chat.service
systemctl restart cti-chat.service

echo "[4/5] nginx"
install -m 644 "$APP/deploy/nginx.conf" /etc/nginx/sites-available/cti
ln -sfn /etc/nginx/sites-available/cti /etc/nginx/sites-enabled/cti
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

echo "[5/5] first collection run"
systemctl start cti-collect.service || true
echo "installed. Status: systemctl status cti-collect.timer; logs: journalctl -u cti-collect -f"
