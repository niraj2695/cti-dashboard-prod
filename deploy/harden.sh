#!/usr/bin/env bash
# Baseline hardening for the CTI dashboard host (Ubuntu Server 24.04 LTS on AWS EC2).
# Run once as root on a fresh instance:  sudo bash deploy/harden.sh <admin-user> "<ssh-public-key>"
#
# This is a starting point mapped to common CIS Ubuntu Linux Benchmark items. The student team
# should extend it and record each control in docs/hardening-checklist.md with evidence.
set -euo pipefail

ADMIN="${1:?admin username required}"
PUBKEY="${2:?ssh public key required}"
ADMIN_CIDRS="${ADMIN_CIDRS:-}"   # optional, e.g. "131.170.0.0/16 203.0.113.7/32" to restrict SSH to RMIT and home

echo "[1/8] packages and automatic security updates"
apt-get update -y && apt-get upgrade -y
apt-get install -y ufw fail2ban unattended-upgrades nginx python3-venv python3-pip git certbot python3-certbot-nginx
dpkg-reconfigure -f noninteractive unattended-upgrades

echo "[2/8] admin user with sudo, key-only"
if ! id "$ADMIN" &>/dev/null; then
  adduser --disabled-password --gecos "" "$ADMIN"
  usermod -aG sudo "$ADMIN"
fi
install -d -m 700 -o "$ADMIN" -g "$ADMIN" "/home/$ADMIN/.ssh"
echo "$PUBKEY" > "/home/$ADMIN/.ssh/authorized_keys"
chmod 600 "/home/$ADMIN/.ssh/authorized_keys"; chown "$ADMIN:$ADMIN" "/home/$ADMIN/.ssh/authorized_keys"

echo "[3/8] sshd: no root, no passwords"
cat > /etc/ssh/sshd_config.d/99-cti-hardening.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
sshd -t && systemctl restart ssh

echo "[4/8] firewall: 443 to the world, 22 restricted, everything else denied"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 443/tcp
ufw allow 80/tcp    # needed for the Let's Encrypt HTTP-01 challenge and the HTTPS redirect
if [ -n "$ADMIN_CIDRS" ]; then
  for c in $ADMIN_CIDRS; do ufw allow from "$c" to any port 22 proto tcp; done
else
  ufw allow 22/tcp; echo "WARNING: SSH open to all; set ADMIN_CIDRS and re-run, or restrict in the AWS security group"
fi
ufw --force enable

echo "[5/8] fail2ban for sshd and nginx"
cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 4
[sshd]
enabled = true
[nginx-http-auth]
enabled = true
[nginx-botsearch]
enabled = true
EOF
systemctl enable --now fail2ban

echo "[6/8] service account and directories"
id cti &>/dev/null || useradd --system --home /srv/cti --shell /usr/sbin/nologin cti
install -d -o cti -g cti -m 750 /srv/cti /srv/cti/data
install -d -o root -g cti -m 750 /etc/cti
[ -f /etc/cti/env ] || { cp "$(dirname "$0")/env.example" /etc/cti/env; chmod 640 /etc/cti/env; chown root:cti /etc/cti/env; }

echo "[7/8] kernel and misc"
cat > /etc/sysctl.d/99-cti.conf <<'EOF'
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
EOF
sysctl --system >/dev/null
echo "Authorised access only. Activity is logged." > /etc/issue.net
sed -i 's|^#\?Banner .*|Banner /etc/issue.net|' /etc/ssh/sshd_config

echo "[8/8] done. Next: deploy/install.sh as the admin user, then certbot --nginx -d <your-domain>"
