#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

INGRESS_SERVER_ID="11111111-1111-4111-8111-111111111111"
EXIT_SERVER_ID="22222222-2222-4222-8222-222222222222"
RELAY_SERVER_ID="33333333-3333-4333-8333-333333333333"
ADMIN_CSRF_TOKEN="csrf-test-token_123"
INGRESS_PUBLIC_IPV4="93.184.216.34"
export INGRESS_SERVER_ID EXIT_SERVER_ID RELAY_SERVER_ID ADMIN_CSRF_TOKEN INGRESS_PUBLIC_IPV4

assert_ok() {
  script="$1"
  output="$($script)"
  printf '%s' "$output" | grep -q "/transport/topology/summary"
  printf '%s' "$output" | grep -q "X-CSRF-Token: ${ADMIN_CSRF_TOKEN}"
}

assert_fails() {
  description="$1"
  shift
  if "$@" >/tmp/guardex-stage1-renderer-test.out 2>/tmp/guardex-stage1-renderer-test.err; then
    echo "Expected failure: $description" >&2
    exit 1
  fi
}

for script in "$ROOT/ops/render-stage1-intent-curl.sh" "$ROOT/ops/render-stage1-rollback-curl.sh"; do
  assert_ok "$script"

  assert_fails "same relay and ingress rejected by $script" \
    env RELAY_SERVER_ID="$INGRESS_SERVER_ID" "$script"

  assert_fails "private ingress address rejected by $script" \
    env INGRESS_PUBLIC_IPV4="10.0.0.1" "$script"

  assert_fails "unsafe csrf rejected by $script" \
    env ADMIN_CSRF_TOKEN="bad'token" "$script"

  assert_fails "unsafe admin api base rejected by $script" \
    env ADMIN_API_BASE="http://api.guardex-vpn.com/v1/admin" "$script"

  assert_fails "invalid backbone port rejected by $script" \
    env BACKBONE_LISTEN_PORT="70000" "$script"

  assert_fails "public tunnel cidr rejected by $script" \
    env INGRESS_TUNNEL_CIDR="8.8.8.8/30" "$script"
done

rm -f /tmp/guardex-stage1-renderer-test.out /tmp/guardex-stage1-renderer-test.err
echo "stage1 renderer smoke tests passed"
