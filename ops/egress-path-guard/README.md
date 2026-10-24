# Authenticated egress data-path recovery

This guard is for an ingress with exactly one exit peer on `gxwg0`. It probes a
1200-byte payload through the authenticated private tunnel every two seconds.
Two failures switch only that peer's endpoint between configured public IPv4 and
IPv6 literals on the existing UDP/443 listener. Keys, addresses, AllowedIPs,
routes and running VPN processes are not changed. A healthy fallback is retained;
there is no periodic disruptive failback. Changes are limited to once per 30s.

It addresses the recovery gap exposed by the Jakarta egress outages: a public
TCP health check or a previously successful WG handshake cannot establish that
the encrypted data path still works. It does **not** claim to identify the
provider's packet-dropping device or increase Moscow's international bandwidth.
It also must not be used to label individual HTTP/client stalls as WG outages.

The configuration contains only public information:

```json
{
  "interface": "gxwg0",
  "peer_public_key": "<existing exit public key>",
  "probe_ip": "10.77.0.14",
  "ensure_underlay_policy": true,
  "listen_port": 51821,
  "endpoints": ["94.249.195.63:443", "[2a14:7c0:1002:19c4::]:443"]
}
```

Before installation, verify both paths with an independent QA WG peer in a
network namespace. Do not inject drops into a production peer. The exit must
allow UDP/443 over IPv6 **only from the ingress's configured IPv6 address**;
retain the existing IPv4 firewall policy. Verify PMTU with a 1200-byte inner
probe and strict HTTPS with exact response hashes, including an existing TCP
connection surviving an isolated QA-only IPv4 drop.

Also validate the **real transport UID**, separately from root ping. Production
WG packets can retain UID 65532 and hit the transport kill-switch; its original
exception allowed only the IPv4 exit. The optional underlay policy heals one
exact IPv6 exception for UID 65532, the configured exit address, the existing WG
source port and UDP destination port 443. Other traffic still hits the existing
kill-switch. Existing markers with broader/different rules are rejected. The
exception is restored if topology reconciliation recreates its table.

The live namespace regression runs its HTTPS client as UID 65532, but moving a
WG device between namespaces can scrub socket ownership. Its report explicitly
records that limitation. It must not be used to claim production owner-policy
acceptance: check real VPN transfers and the narrowly scoped rule's counter too.

Install `watchdog.py` in `/opt/guardex-egress-path/`, its root-owned configuration
in `/etc/guardex-egress-path/config.json`, and the unit in `/etc/systemd/system/`.
Run `python3 watchdog.py --config <file> --check` before starting the unit. The
guard refuses foreign/shared peers and unknown runtime endpoints. It reads only
public peer metadata, never the private key. Full topology reconciliation may
restore the primary endpoint; the next observed data-path failure still activates
the configured fallback.

Rollback: stop and disable `guardex-egress-path.service`; restore the original
peer endpoint with `wg set gxwg0 peer <public-key> endpoint 94.249.195.63:443`.
Remove only the added source-specific IPv6 UDP/443 firewall permission after
the IPv4 private probe succeeds. Do not restart the shared exit interface.
Remove only the rule marked `guardex_egress_ipv6_underlay` from the ingress output
chain if rolling the feature back; retain every other transport rule.

Validation: `python3 -m unittest -v test_watchdog.py` checks transient loss,
failure reset, cooldown, absence of failback, identity/endpoint refusal and that
the peer mutation changes only the endpoint. The live namespace regression must
be recorded separately from unit tests and production observation.
Run the opt-in live regression with `GUARDEX_EGRESS_NETWORK_TEST=1 python3
test_network.py`. It requires existing root SSH access to the owned Jakarta and
exit servers, refuses a conflicting QA route, creates an independent temporary
key/peer, and cleans its namespace, firewall rules and exit route. It asserts a
real guard event after the fault, preventing authenticated endpoint roaming
from producing a false-positive failover result.
