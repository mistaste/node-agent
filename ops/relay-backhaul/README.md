# Relay UDP backhaul

An authenticated WireGuard link carries the relay's upstream TCP connection
when the relay provider loses TCP packets but delivers UDP reliably. The blind
relay and the client keep their original addresses, SNI, certificate checks,
credentials and end-to-end TLS. This does not change the ingress-to-exit `gxwg0`
backbone or let the relay decrypt VPN traffic.

Use a separate `gxrelay0` interface, UDP 51839, MTU 1280 and private prefix
10.79.240.0/28. Generate each private key on its own host with mode 0600; never
commit or copy it into the deployment bundle. Each peer authorizes only the
other host's private /32. On ingresses allow TCP/443 and ICMP from the relay's
private address, allow established replies, and reject all other traffic from
this interface. Reject forwarding into and out of the interface on every host.

Persist the interface with `wg-quick@gxrelay0`, including its input/forward
firewall guard. To retain Ubuntu's wg-quick AppArmor confinement, place the
non-secret guard at `/etc/wireguard/gxrelay0-filter.nft` and feed nft from stdin:

```ini
PostUp = /usr/sbin/nft -f - < /etc/wireguard/gxrelay0-filter.nft
PostDown = /usr/sbin/nft delete table inet guardex_relay_backhaul_guard
```

Do not disable or broaden AppArmor for this deployment. Install `watchdog.py` at
`/usr/local/lib/guardex-relay-backhaul/watchdog.py` and its service on the relay.
Its root-owned `/etc/guardex-relay-backhaul/config.json` contains only:

```json
{"interface":"gxrelay0","peers":[{"public_ip":"5.255.124.73","private_ip":"10.79.240.2"}]}
```

The watchdog checks private reachability every five seconds. Two successful
checks select a peer, two failures restore the original TCP path. Updates to
the destination map are atomic. The map rewrites only outgoing TCP/443 for the
listed public ingress IPs and source-NATs them to the relay's private address;
the original public source would otherwise fail the WireGuard peer's /32 guard.
Use `ingress-filter.nft` on receivers and `relay-filter.nft` on the relay.
Existing connections retain their conntrack mapping;
failover affects new connections. Stopping/crashing the watchdog removes its
table, including when the WireGuard service stops. Other relay rules, including
the Jakarta SSH fallback, are retained and become the fallback automatically.

Before selecting a route, verify the unchanged public hostname certificate and
authenticated H2 CONNECT transfer with a complete digest over the private link.
Then verify the same transfer through the actual public relay. Test watchdog
failure/recovery and check that public web/API behavior remains unchanged.

Rollback on the relay: disable/stop `guardex-relay-backhaul.service`, delete only
`table ip guardex_relay_backhaul` if present, then stop `wg-quick@gxrelay0` on
both hosts. Retain the previous paths and root-only configuration backups.
Never flush the host ruleset or alter the `guardex_transport`/`gxwg0` state.

Checks: `python3 ops/relay-backhaul/test_watchdog.py`, Linux/root
`python3 -m unittest discover -s ops/relay-backhaul -p test_network.py -v`,
`nft -c -f` on the generated map and guard rules, and `systemd-analyze verify`
for the installed service. The network regression creates disposable namespaces;
its negative control removes source NAT and must fail, while the full rules must
deliver the complete 2 MiB response through the peer's source guard.
