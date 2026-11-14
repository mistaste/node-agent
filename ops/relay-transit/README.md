# Fixed Germany transit

This narrowly scoped fallback avoids the variable Moscow → Frankfurt public
TCP path by using the existing authenticated Moscow → Dronten WireGuard hop,
then Dronten → Frankfurt TCP/443. It preserves end-to-end TLS, credentials,
the requested Frankfurt ingress, and the existing German exit. Dronten cannot
decrypt or choose destinations: the forwarder accepts only 10.79.240.1 on its
private WireGuard address and forwards only to Frankfurt:443. It is not public.

The selector installs a dedicated OUTPUT DNAT for Frankfurt:443 before the
existing backhaul selector, plus exact private-source SNAT. Other destinations,
UDP/HTTP3, ingress listeners, default routes and exits are untouched. Existing
connections retain their conntrack mapping; only new connections take a change.

Configuration, root-owned and not writable by others:

```json
{"role":"forward","public_address":"207.241.172.230","via_address":"10.79.240.2","hostname":"frankfurt.de.guardex-vpn.com"}
```

Use `role: select` on Moscow. Install `transit.py` under
`/usr/local/lib/guardex-relay-transit/`, configuration at
`/etc/guardex-relay-transit.json`, and the role-specific unit. Both require the
existing `wg-quick@gxrelay0` and its firewall guard. The forward unit runs as
`nobody`; only its root pre/post helpers add/remove the exact peer/port allowance.
It enforces a connection cap, bounded buffers, keepalives and write deadlines;
it does not impose a five-minute lifetime or cut healthy idle streams.

Before enabling the selector, validate signed/digest-verified full transfers
through the private hop in both directions and end-to-end TLS identity. The
selector's subsequent TLS check is liveness only, not a throughput proof. Three
healthy checks enable the route; two failures remove only this dedicated table,
restoring the pre-existing public path. SIGTERM and ExecStopPost also remove it.
There is no TLS verification bypass or automatic credential provisioning.

Rollback: stop/disable the select service first (verify its table is absent),
then stop/disable forward. The forward unit removes its comment-bound firewall
allowance. Keep Germany's previously disabled private backhaul setting unchanged.

Tests: `python3 -m unittest discover -s ops/relay-transit -p 'test_*.py'`.
`test_network.py` additionally needs disposable Linux root network namespaces;
it exercises real DNAT/SNAT, precedence over the old selector and a negative
source-NAT control without touching the host network namespace.
