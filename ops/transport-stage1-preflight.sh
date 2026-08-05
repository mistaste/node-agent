#!/usr/bin/env sh
set -eu

ROOT="${GUARDEX_NODE_ROOT:-/opt/guardex-node}"
COMPOSE="${ROOT}/docker-compose.yml"
TT_ROOT="${TRUSTTUNNEL_ROOT:-${ROOT}/data/trusttunnel}"
TOPOLOGY_ROOT="${TOPOLOGY_ROOT:-${ROOT}/data/topology}"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

warn() {
  echo "WARN: $*" >&2
}

[ "$(id -u)" -eq 0 ] || fail "run as root on the node"
[ -d "$ROOT" ] || fail "node root does not exist: $ROOT"
[ -f "$COMPOSE" ] || fail "docker-compose.yml not found: $COMPOSE"
command -v docker >/dev/null 2>&1 || fail "docker is not installed"
docker compose version >/dev/null 2>&1 || fail "docker compose plugin is not available"
command -v nft >/dev/null 2>&1 || fail "nftables is not installed"
command -v ip >/dev/null 2>&1 || fail "iproute2 is not installed"
command -v wg >/dev/null 2>&1 || fail "wireguard-tools is not installed"

if systemctl is-enabled guardex-trusttunnel.service >/dev/null 2>&1; then
  fail "legacy guardex-trusttunnel.service is enabled; Stage 1 uses the container runner"
fi

if docker compose -f "$COMPOSE" config 2>/dev/null | grep -q '/var/run/docker.sock.*topology-agent'; then
  fail "topology-agent must never mount docker.sock"
fi

install -d -m 0700 "$TT_ROOT" "$TOPOLOGY_ROOT"

if [ -e "${TT_ROOT}/credentials.toml" ]; then
  mode="$(stat -c '%a' "${TT_ROOT}/credentials.toml" 2>/dev/null || stat -f '%Lp' "${TT_ROOT}/credentials.toml")"
  [ "$mode" = "600" ] || fail "TrustTunnel credentials.toml must stay 0600 before enabling runner"
fi

if ip link show dev gxwg0 >/dev/null 2>&1; then
  warn "gxwg0 already exists; verify it belongs to Guardex before applying Stage 1"
fi

echo "OK: Stage 1 node preflight passed"
