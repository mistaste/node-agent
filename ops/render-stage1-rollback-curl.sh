#!/bin/sh
set -eu

# Prints, but never executes, the admin API calls for a safe Stage 1 rollback.
# Rollback order is exposure-first:
#   1) disable blind relay route and relay role;
#   2) disable backbone;
#   3) disable ingress/exit roles.
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
#   ADMIN_COOKIE_FILE=/path/to/admin-cookies.txt
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

shell_quote() {
  printf "'"
  printf '%s' "$1" | sed "s/'/'\\\\''/g"
  printf "'"
}

role_body() {
  server_id="$(json_string "$1")"
  role="$(json_string "$2")"
  printf '{"server_id":"%s","role":"%s","enabled":false}' "$server_id" "$role"
}

backbone_body() {
  printf '{"ingress_server_id":"%s","exit_server_id":"%s","ingress_tunnel_address":"%s","exit_tunnel_address":"%s","listen_port":%s,"enabled":false}' \
    "$(json_string "$INGRESS_SERVER_ID")" \
    "$(json_string "$EXIT_SERVER_ID")" \
    "$(json_string "$INGRESS_TUNNEL_CIDR")" \
    "$(json_string "$EXIT_TUNNEL_CIDR")" \
    "$BACKBONE_LISTEN_PORT"
}

relay_body() {
  printf '{"relay_server_id":"%s","ingress_server_id":"%s","ingress_address":"%s","tcp_enabled":true,"udp_enabled":true,"enabled":false}' \
    "$(json_string "$RELAY_SERVER_ID")" \
    "$(json_string "$INGRESS_SERVER_ID")" \
    "$(json_string "$INGRESS_PUBLIC_IPV4")"
}

curl_post() {
  path="$1"
  body="$2"
  printf "curl -fsS %s \\\\\n" "$(shell_quote "${ADMIN_API_BASE}${path}")"
  if [ -n "${ADMIN_COOKIE_FILE:-}" ]; then
    printf "  -b %s \\\\\n" "$(shell_quote "$ADMIN_COOKIE_FILE")"
  fi
  cat <<EOF
  -H 'Content-Type: application/json' \\
  -H 'X-CSRF-Token: ${ADMIN_CSRF_TOKEN}' \\
  -H "Idempotency-Key: stage1-rollback-\$(uuidgen)" \\
  --data '${body}'
EOF
}

require ADMIN_CSRF_TOKEN
require INGRESS_SERVER_ID
require EXIT_SERVER_ID
require RELAY_SERVER_ID
require INGRESS_PUBLIC_IPV4

cat <<EOF
# Stage 1 rollback intent plan.
# Review every command before running. These commands require an existing
# browser/admin session cookie. Set ADMIN_COOKIE_FILE to render curl -b safely.
# This script intentionally does not handle credentials or execute anything.

EOF

if [ -z "${ADMIN_COOKIE_FILE:-}" ]; then
  cat <<EOF
# WARNING: ADMIN_COOKIE_FILE is not set. The rendered commands still need an
# admin session cookie, for example: ADMIN_COOKIE_FILE=/tmp/admin-cookies.txt

EOF
fi

cat <<EOF
# 1) Remove public exposure first. This stops new tester catalogues from
# receiving relay_addresses before the private path is dismantled.
EOF
curl_post "/transport/topology/relay-routes" "$(relay_body)"
curl_post "/transport/topology/roles" "$(role_body "$RELAY_SERVER_ID" relay)"

cat <<EOF

# 2) Disable the private ingress -> exit backbone. Nodes will remove gxwg0,
# policy rule priority 100 and Guardex-owned nftables rules on their next pull.
EOF
curl_post "/transport/topology/backbone-links" "$(backbone_body)"

cat <<EOF

# 3) Tombstone ingress and exit roles after the relay and backbone are disabled.
EOF
curl_post "/transport/topology/roles" "$(role_body "$INGRESS_SERVER_ID" ingress)"
curl_post "/transport/topology/roles" "$(role_body "$EXIT_SERVER_ID" exit)"

cat <<EOF

# 4) Readiness after rollback:
curl -fsS '${ADMIN_API_BASE}/transport/topology/summary'
EOF
