# Node capacity and account fairness

## Deployed scope, 29 October 2026

Account shaping is enabled **only on Wroclaw, Poland (212.127.91.131)**.
Other reachable nodes retain their existing fq_codel flow queues and no account
broker. Amsterdam and Istanbul are disabled and inaccessible by SSH.

The pilot shares one payload budget between TrustTunnel and NaiveProxy after
authentication. Profile UUIDs map to HMAC account identities; multiple profiles,
devices, streams, protocols and both directions consume the same account share.
Idle accounts consume no share. Low-demand accounts receive what they need;
other accounts borrow unused capacity. Client IP is never the account identity.

## Budget and load response

The initial and maximum aggregate upload-plus-download budget is **96 Mbps**,
with a **32 Mbps** floor. This is payload bandwidth counted once, rather than
NIC RX plus TX. Two demanding accounts normally receive about half each.

The governor samples host CPU every five seconds. Three samples at or above
80% reduce the budget by 15%; six samples at or below 60% increase it by 5%, up
to 96 Mbps. The earlier 200 Mbps experiment failed the stream-count fairness
criterion, so it is not enabled. Higher provisional node estimates are not
validated account-scheduling limits.

The broker writes root-private counters to
`/var/lib/guardex-account-qos/stats.json`, including budget, reason, pending
requests and unknown identities. The mapping exporter refreshes every 15 seconds;
the broker reloads the last valid mapping without a database lookup per packet.
The current pilot has no public per-account metrics endpoint or admin UI.

## Failure behavior and rollback

Native transports continue forwarding when the private broker is unavailable.
They report ACCOUNT_QOS_UNAVAILABLE / ACCOUNT_QOS_RECOVERED. This fail-open
behavior disables shaping while preserving the VPN data plane.

Immediate shaping disable on Poland:

```sh
systemctl stop guardex-account-qos
```

Full pilot rollback restores the saved native transport images and persistent
compose overrides, with no retired engine recreation:

```sh
python3 /var/lib/guardex-remediation/account-qos-20261028/rollback.py
```

RuntimeDirectoryPreserve keeps the mounted directory stable across broker
restarts. ExecStartPre removes a stale socket after an unclean exit. The local
endpoint group must resolve to gid 65532; activation creates it when absent.

## Acceptance evidence

Native-only isolated tests used the production 0.35 CPU limit on each endpoint
container and 20-second transfer windows:

| Workload | Account A | Account B |
| --- | --- | --- |
| One account, one stream | 92.61 Mbps | idle |
| A has 16 streams, B has one | 47.01 Mbps | 46.48 Mbps |
| A spans two profiles and both native protocols | 47.46 Mbps | 46.35 Mbps |

A bulk downloader reached 93.50 Mbps while a separate low-demand account
completed 35/35 SHA-verified short requests, p95 0.367 seconds, max 0.414 seconds.
Unknown identity requests were zero. Unit tests cover scheduler fairness,
idle borrowing, mapping reload, cancellation, directions and CPU hysteresis.

Stopping the isolated broker during 20 MiB native transfers preserved both
SHA-256 hashes. Public-port authenticated TrustTunnel and Naive probes on Poland
passed with the expected exit IP. Graceful restart and SIGKILL of the production
broker preserved both checked transfers; the latter restarted automatically
after two seconds and subsequent traffic was accounted again.

These checks establish this bounded pilot, not a fleet capacity guarantee.
UDP throughput, sustained real-user mixed workloads and a higher budget require
separate acceptance before any wider rollout.
