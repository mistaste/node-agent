#!/bin/sh
set -eu

# Restrict the privileged node-agent API to the Guardex controller. This script
# is intentionally idempotent: systemd runs it at boot and operators may run it
# again after changing /etc/guardex/node-firewall.conf.
CONTROLLER_ORIGIN_IP="${CONTROLLER_ORIGIN_IP:-80.241.216.139}"
AGENT_PORT="${AGENT_PORT:-8099}"
CHAIN="GUARDEX_AGENT"

# Reject malformed IPv4 addresses instead of letting iptables interpret them.
if ! printf '%s\n' "$CONTROLLER_ORIGIN_IP" | awk -F. '
    NF != 4 { exit 1 }
    {
        for (i = 1; i <= 4; i++) {
            if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) exit 1
        }
    }
'; then
    echo "invalid CONTROLLER_ORIGIN_IP: expected four decimal octets" >&2
    exit 1
fi

case "$AGENT_PORT" in
    ''|*[!0-9]*)
        echo "invalid AGENT_PORT: expected an integer" >&2
        exit 1
        ;;
esac
[ "$AGENT_PORT" -ge 1 ] && [ "$AGENT_PORT" -le 65535 ] || {
    echo "invalid AGENT_PORT: expected a value between 1 and 65535" >&2
    exit 1
}

command -v iptables >/dev/null 2>&1 || {
    echo "iptables is required" >&2
    exit 1
}

apply_ipv4() {
    iptables -w 5 -N "$CHAIN" 2>/dev/null || true
    iptables -w 5 -F "$CHAIN"
    iptables -w 5 -A "$CHAIN" -p tcp -s "$CONTROLLER_ORIGIN_IP" --dport "$AGENT_PORT" -j ACCEPT
    iptables -w 5 -A "$CHAIN" -p tcp --dport "$AGENT_PORT" -j DROP
    iptables -w 5 -A "$CHAIN" -j RETURN
    iptables -w 5 -C INPUT -j "$CHAIN" 2>/dev/null || iptables -w 5 -I INPUT 1 -j "$CHAIN"
}

apply_ipv6() {
    # There is no public IPv6 controller endpoint. Deny the management port for
    # every IPv6 source so it cannot bypass the IPv4 allowlist.
    command -v ip6tables >/dev/null 2>&1 || {
        echo "ip6tables is required" >&2
        exit 1
    }
    ip6tables -w 5 -N "$CHAIN" 2>/dev/null || true
    ip6tables -w 5 -F "$CHAIN"
    ip6tables -w 5 -A "$CHAIN" -p tcp --dport "$AGENT_PORT" -j DROP
    ip6tables -w 5 -A "$CHAIN" -j RETURN
    ip6tables -w 5 -C INPUT -j "$CHAIN" 2>/dev/null || ip6tables -w 5 -I INPUT 1 -j "$CHAIN"
}

apply_ipv4
apply_ipv6
