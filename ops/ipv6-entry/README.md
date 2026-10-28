# Optional client IPv6 entries

This is a separate IPv6-only TCP/443 HAProxy listener forwarding opaque TLS to
the existing IPv4 SNI listener. It does not change relay, WireGuard, routing or
UDP/H3. The API advertises fresh entries only to the tester group, retaining IPv4.

The root-owned controller inventory contains server IDs and public IPv4 SSH
addresses. Update it through provisioning when adding/removing a node; the timer
discovers IPv6 addresses and checks all provisioned nodes every minute. Current
inventory covers the six active TrustTunnel servers. No IPv6 address is invented.

`fleet.py --install --inventory /etc/guardex-ipv6-entry/inventory.json` publishes
an atomic cache with a three-minute expiry. Remote SSH uses a controller-only
private key, pinned host keys and a forced bounded agent command restricted to
the controller source address. The cache contains public readiness data only.

Verification uses another server with IPv6 and checks TCP, TLS PKI, hostname,
h2 ALPN and the configured certificate SPKI. This proves entry TLS reachability;
authenticated tunnel, DNS, egress and recovery are separate iOS diagnostic tests.
Missing address, route, listener, probe or verifier access cannot remove IPv4.

## Rollback

1. Disable the controller timer: `systemctl disable --now guardex-ipv6-entry.timer`.
2. Remove the published capabilities file. After its expiry the API omits IPv6
   even if a stale copy remains. Existing authenticated connections are unaffected.
3. On nodes managed by this component, `systemctl disable --now guardex-ipv6-entry.service`.
   The stop script verifies its exact configuration before terminating only its
   own HAProxy PID. Do not stop the shared transport container or IPv4 listener.
4. Remove only the `guardex-ipv6-entry-verifier-20261028` authorized-key line and
   these component files when no longer required. Helsinki's earlier temporary
   pilot service has its own expiry/rollback; never stop an unrelated listener.

A listener that already occupies IPv6/443 is left in place and must pass external
verification. Cache state `verified` is never interpreted as proof of no leaks.
