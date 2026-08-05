#!/bin/sh
set -eu

# Prints, but never executes, the admin API calls for a Stage 1 canary:
# relay -> ingress TrustTunnel -> private WireGuard backbone -> exit.
#
# Required environment:
#   ADMIN_CSRF_TOKEN
#   INGRESS_SERVER_ID
#   EXIT_SERVER_ID
#   RELAY_SERVER_ID
#   INGRESS_PUBLIC_IPV4
#
# Optional:
#   ADMIN_API_BASE=https://api.guardex-vpn.com/v1/admin
#   INGRESS_TUNNEL_CIDR=10.77.0.1/30
#   EXIT_TUNNEL_CIDR=10.77.0.2/30
#   BACKBONE_LISTEN_PORT=51820

ADMIN_API_BASE="${ADMIN_API_BASE:-https://api.guardex-vpn.com/v1/admin}"
INGRESS_TUNNEL_CIDR="${INGRESS_TUNNEL_CIDR:-10.77.0.1/30}"
EXIT_TUNNEL_CIDR="${EXIT_TUNNEL_CIDR:-10.77.0.2/30}"
BACKBONE_LISTEN_PORT="${BACKBONE_LISTEN_PORT:-51820}"

require() {
  name="$1"
  eval "value=\${$name:-}"
  if [ -z "$value" ]; then
    echo "Missing required environment: $name" >&2
    exit 2
  fi
}

json_string() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

role_body() {
  server_id="$(json_string "$1")"
  role="$(json_string "$2")"
  enabled="$3"
  printf '{"server_id":"%s","role":"%s","enabled":%s}' "$server_id" "$role" "$enabled"
}

backbone_body() {
  enabled="$1"
  printf '{"ingress_server_id":"%s","exit_server_id":"%s","ingress_tunnel_address":"%s","exit_tunnel_address":"%s","listen_port":%s,"enabled":%s}' \
    "$(json_string "$INGRESS_SERVER_ID")" \
    "$(json_string "$EXIT_SERVER_ID")" \
    "$(json_string "$INGRESS_TUNNEL_CIDR")" \
    "$(json_string "$EXIT_TUNNEL_CIDR")" \
    "$BACKBONE_LISTEN_PORT" \
    "$enabled"
}

relay_body() {
  enabled="$1"
  printf '{"relay_server_id":"%s","ingress_server_id":"%s","ingress_address":"%s","tcp_enabled":true,"udp_enabled":true,"enabled":%s}' \
    "$(json_string "$RELAY_SERVER_ID")" \
    "$(json_string "$INGRESS_SERVER_ID")" \
    "$(json_string "$INGRESS_PUBLIC_IPV4")" \
    "$enabled"
}

curl_post() {
  path="$1"
  body="$2"
  cat <<EOF
curl -fsS '${ADMIN_API_BASE}${path}' \\
  -H 'Content-Type: application/json' \\
  -H 'X-CSRF-Token: ${ADMIN_CSRF_TOKEN}' \\
  -H "Idempotency-Key: stage1-\$(uuidgen)" \\
  --data '${body}'
EOF
}

require ADMIN_CSRF_TOKEN
require INGRESS_SERVER_ID
require EXIT_SERVER_ID
require RELAY_SERVER_ID
require INGRESS_PUBLIC_IPV4

cat <<EOF
# Stage 1 canary intent plan.
# Review every command before running. These commands require an existing
# browser/admin session cookie; this script intentionally does not handle
# credentials or execute anything.

# 1) Create disabled roles first. Nodes can report WireGuard public keys without
# exposing relay addresses to tester catalogues.
EOF
curl_post "/transport/topology/roles" "$(role_body "$INGRESS_SERVER_ID" ingress false)"
curl_post "/transport/topology/roles" "$(role_body "$EXIT_SERVER_ID" exit false)"

cat <<EOF

# 2) Create the disabled backbone. It must stay disabled until both roles show
# WireGuard public keys in /transport/topology/summary.
EOF
curl_post "/transport/topology/backbone-links" "$(backbone_body false)"

cat <<EOF

# 3) Enable ingress and exit roles, then enable the backbone after both nodes
# have applied the desired role revision.
EOF
curl_post "/transport/topology/roles" "$(role_body "$INGRESS_SERVER_ID" ingress true)"
curl_post "/transport/topology/roles" "$(role_body "$EXIT_SERVER_ID" exit true)"
curl_post "/transport/topology/backbone-links" "$(backbone_body true)"

cat <<EOF

# 4) Create relay intent disabled first. Enable it only after ingress, exit and
# backbone are all ready. Relay always targets ingress TCP/UDP 443 only.
EOF
curl_post "/transport/topology/roles" "$(role_body "$RELAY_SERVER_ID" relay false)"
curl_post "/transport/topology/relay-routes" "$(relay_body false)"

cat <<EOF

# 5) Canary exposure: enable the relay role and route, then verify tester signed
# catalogues contain relay_addresses and regular users do not.
EOF
curl_post "/transport/topology/roles" "$(role_body "$RELAY_SERVER_ID" relay true)"
curl_post "/transport/topology/relay-routes" "$(relay_body true)"

cat <<EOF

# 6) Readiness after each block:
curl -fsS '${ADMIN_API_BASE}/transport/topology/summary'
EOF
