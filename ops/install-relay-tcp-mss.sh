#!/usr/bin/env bash
set -euo pipefail

[[ "$(id -u)" == 0 ]] || { echo "Run as root" >&2; exit 1; }
policy_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/firewall" && pwd)"
command -v nft >/dev/null
command -v python3 >/dev/null

python3 "$policy_root/guardex-relay-tcp-mss.py" check "$policy_root/guardex-relay-tcp-mss.nft"

# Preserve only this feature's prior files. Existing SSH, admission, topology
# and firewall configuration are never replaced by this installer.
policy_backup="$(mktemp -d /var/backups/guardex-relay-tcp-mss.XXXXXX)"
for path in /usr/local/sbin/guardex-relay-tcp-mss /etc/guardex/relay-tcp-mss.nft /etc/systemd/system/guardex-relay-tcp-mss.service; do
    if [[ -e "$path" ]]; then
        cp --parents -a "$path" "$policy_backup/"
    fi
done
if [[ ! -d /etc/guardex ]]; then
    install -d -m 0755 /etc/guardex
fi
install -m 0755 "$policy_root/guardex-relay-tcp-mss.py" /usr/local/sbin/guardex-relay-tcp-mss
install -m 0644 "$policy_root/guardex-relay-tcp-mss.nft" /etc/guardex/relay-tcp-mss.nft
install -m 0644 "$policy_root/guardex-relay-tcp-mss.service" /etc/systemd/system/guardex-relay-tcp-mss.service
systemd-analyze verify /etc/systemd/system/guardex-relay-tcp-mss.service
systemctl daemon-reload
systemctl enable guardex-relay-tcp-mss.service
if systemctl is-active --quiet guardex-relay-tcp-mss.service; then
    systemctl reload guardex-relay-tcp-mss.service
else
    systemctl start guardex-relay-tcp-mss.service
fi
echo "Relay TCP policy installed. Prior files: $policy_backup"
echo "Rollback: systemctl disable --now guardex-relay-tcp-mss.service"
