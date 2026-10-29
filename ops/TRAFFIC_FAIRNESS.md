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

The initial and maximum aggregate upload-plus-download budget is **256 Mbps**,
with a **32 Mbps** floor. This is payload bandwidth counted once, rather than
NIC RX plus TX. Two demanding accounts normally receive about half each.

The governor samples host CPU every five seconds. Three samples at or above
80% reduce the budget by 15%; six samples at or below 60% increase it by 5%, up
to 256 Mbps. The original 200 Mbps test failed stream-count fairness. The
current scheduler preserves a bulk account's turn across an idle gap of at most
8 milliseconds after sustained grants, preventing many queued streams from
stealing a single stream's next turn. Low-demand short requests do not reserve
a bulk share. Unused capacity is borrowed after this bounded gap.

Poland's two native endpoint containers have a persistent 0.75 CPU quota each;
the former 0.35 quota caused frequent cgroup throttling at the higher budget.
Other nodes retain their existing quotas. Their transport binaries are unchanged.

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

## Previous 96 Mbps acceptance evidence

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

## Raised ceiling acceptance, 29 October 2026

The higher-budget tests used the exact production native engine images and the
new scheduler. Each native endpoint had a 0.75 CPU quota.

| Workload at 256 Mbps | Account A | Account B |
| --- | --- | --- |
| TrustTunnel, 32 streams versus one, 45 seconds | 109.50 Mbps | 104.12 Mbps |
| NaiveProxy, 16 streams versus one, 45 seconds | 106.64 Mbps | 104.09 Mbps |
| A spans two profiles and both protocols, 45 seconds | 110.54 Mbps | 110.61 Mbps |

A separate low-demand account completed 71/71 SHA-verified short requests while
the bulk account reached 234.40 Mbps: p95 0.443 seconds, maximum 1.481 seconds.
The single-stream 1 GiB transfer completed in 41.006 seconds (209.48 Mbps over its
actual duration). The test origin's 1 GiB cap ended that case before its nominal
45-second window; it must not be divided by the full nominal window.

Host CPU averaged about 66% during the load run, with isolated peaks around 85%;
the CPU governor kept the tested budget at 256 Mbps. Unknown identity requests
were zero. These are bounded workload checks, not a promise of identical speed
from every client network or a sustained capacity guarantee.

`set-poland-capacity.py` snapshots the current broker binary/unit and endpoint
quotas, changes the persistent Poland-only compose override, and updates CPU
quotas without recreating VPN containers. It verifies their images and start
timestamps are unchanged. Its `--rollback` restores the previous budget, binary
and quotas. A scheduled ten-minute rollback protects live acceptance until the
operator cancels it after validation. The existing full pilot rollback also
removes the capacity override. A 50 ms socket-absent window during broker swaps
lets existing native clients continue forwarding during the swap. Live acceptance
checks changed 256 → 96 → 256 Mbps while both native protocols were actively
transferring 20 MiB: all payloads completed with correct SHA-256, and neither
transport container restarted.
