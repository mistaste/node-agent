#!/usr/bin/env sh
set -eu

ROOT="${GUARDEX_NODE_ROOT:-/opt/guardex-node}"
COMPOSE="${ROOT}/docker-compose.yml"
STAGE1_COMPOSE="${STAGE1_COMPOSE:-${ROOT}/docker-compose.stage1.yml}"
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

if [ -f "$STAGE1_COMPOSE" ]; then
  rendered="$(docker compose -f "$COMPOSE" -f "$STAGE1_COMPOSE" config 2>/dev/null)"
  printf '%s\n' "$rendered" | awk '
    /^[[:space:]]{2}topology-agent:/ { svc="topology-agent" }
    /^[[:space:]]{2}trusttunnel-runner:/ { svc="trusttunnel-runner" }
    /^[[:space:]]{2}node-agent:/ { svc="node-agent" }
    /^[[:space:]]{2}[A-Za-z0-9_.-]+:/ && $1 !~ /^(topology-agent|trusttunnel-runner|node-agent):$/ { svc="" }
    svc == "topology-agent" && /docker\.sock/ { bad_socket=1 }
    svc == "topology-agent" && /NET_ADMIN/ { topology_net_admin=1 }
    svc == "topology-agent" && /NET_BIND_SERVICE/ { bad_topology_bind=1 }
    svc == "trusttunnel-runner" && /NET_ADMIN/ { bad_runner_net_admin=1 }
    svc == "trusttunnel-runner" && /NET_BIND_SERVICE/ { runner_bind=1 }
    svc == "node-agent" && /NET_ADMIN/ { bad_node_admin=1 }
    svc == "node-agent" && /NET_BIND_SERVICE/ { bad_node_bind=1 }
    svc == "node-agent" && /TRUSTTUNNEL_PROCESS_MODE: external/ { external=1 }
    END {
      if (bad_socket) exit 10
      if (!topology_net_admin) exit 11
      if (bad_topology_bind) exit 12
      if (bad_runner_net_admin) exit 13
      if (!runner_bind) exit 14
      if (!external) exit 15
      if (bad_node_admin) exit 16
      if (bad_node_bind) exit 17
    }
  ' || case "$?" in
    10) fail "topology-agent must never mount docker.sock" ;;
    11) fail "topology-agent must explicitly receive NET_ADMIN in Stage 1 override" ;;
    12) fail "topology-agent must not receive NET_BIND_SERVICE" ;;
    13) fail "trusttunnel-runner must not receive NET_ADMIN" ;;
    14) fail "trusttunnel-runner must explicitly receive NET_BIND_SERVICE" ;;
    15) fail "node-agent must delegate TrustTunnel process in Stage 1 override" ;;
    16) fail "node-agent must not receive NET_ADMIN in Stage 1 override" ;;
    17) fail "node-agent must not receive NET_BIND_SERVICE in Stage 1 override" ;;
    *) fail "Stage 1 compose override is invalid" ;;
  esac
else
  warn "Stage 1 compose override not found: $STAGE1_COMPOSE"
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
