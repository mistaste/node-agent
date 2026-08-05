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

is_usable_public_ipv4() {
  value="$1"
  old_ifs="$IFS"
  IFS=.
  # shellcheck disable=SC2086
  set -- $value
  IFS="$old_ifs"
  [ "$#" -eq 4 ] || return 1
  for octet in "$@"; do
    case "$octet" in
      ''|*[!0-9]*) return 1 ;;
      0[0-9]*) return 1 ;;
    esac
    [ "$octet" -le 255 ] || return 1
  done
  a="$1"
  b="$2"
  [ "$a" -ne 0 ] || return 1
  [ "$a" -ne 10 ] || return 1
  [ "$a" -ne 127 ] || return 1
  [ "$a" -lt 224 ] || return 1
  [ "$a" -ne 100 ] || [ "$b" -lt 64 ] || [ "$b" -gt 127 ] || return 1
  [ "$a" -ne 169 ] || [ "$b" -ne 254 ] || return 1
  [ "$a" -ne 172 ] || [ "$b" -lt 16 ] || [ "$b" -gt 31 ] || return 1
  [ "$a" -ne 192 ] || [ "$b" -ne 0 ] || return 1
  [ "$a" -ne 192 ] || [ "$b" -ne 168 ] || return 1
  [ "$a" -ne 198 ] || [ "$b" -ne 18 ] || return 1
  [ "$a" -ne 198 ] || [ "$b" -ne 19 ] || return 1
  [ "$a" -ne 198 ] || [ "$b" -ne 51 ] || return 1
  [ "$a" -ne 203 ] || [ "$b" -ne 0 ] || return 1
  return 0
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

if ! is_usable_public_ipv4 "$INGRESS_PUBLIC_IPV4"; then
  echo "INGRESS_PUBLIC_IPV4 must be an ordinary public IPv4 address, not private/reserved/documentation: $INGRESS_PUBLIC_IPV4" >&2
  exit 2
fi

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
