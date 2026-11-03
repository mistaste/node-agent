# Migration139 bounded operational qualification

This supersedes the migration138 speed-only/no-return packet. No production
flags, real-account eligibility/counters/history or fleet restart were changed.

## Required protocol and accounting

Deploy ALL API workers and migrations through139 before the new broker.
Spendable responses require settlement_version=1 and database-recomputed
valid_for_ms. Initial credit is demand-sized; sustained demand grows to4MiB.
Each grant keeps its original <=5s monotonic deadline; refill cannot extend it.

Only broker-proven never-engine-issued credit can return. Detach precedes the
close RPC. The transaction binds the original node, boot, request, client,
account and UTC period; immutable tombstones make identical closes idempotent,
reject conflicting/foreign closes and deny closed-reserve replay. Old-period
returns cannot fund the current month. Failed acquisitions reuse their original
identity, and recovered never-issued results are closed rather than forwarded.
No server-side expiry refund or restoration of spendable credit after crash.

Funded unexpired leases retain hard-account membership so the last paid batch
is not revoked early. This creates no additional quota: allocator exhaustion
still returns zero. Other eligibility/route gates and legacy admission remain.

## Measured cost and capacity

All quantities below are bytes. The control-capacity workload uses synthetic
engine grants through real broker processes, verified TLS and PostgreSQL; it is
not a claim that32MiB traversed an actual VPN data path.

| Bounded case | Engine-model bytes | Net ledger charge | Residual |
| --- | --- | --- | --- |
| 138 baseline:17 credentials, one5.2s pause | 4,129 | 2,228,224 | 2,224,095 excess |
| 139 same small-flow fixture after explicit close | 4,129 | 4,129 | 0 |
| 16 low-volume accounts, pause/resume | 32 | 32 | 0 |
| Expired unused burst | 2,048 | 2,048 | 0 |
| Graceful broker stop | 2,048 | 2,048 | 0 |
| Abrupt crash and new boot | 2,049 | 4,033 | 1,984 unknown cache, kept charged |
| 32 concurrent accounts with reply loss/jitter | 33,554,432 | 33,554,432 | 0 unresolved |

Final marker-enabled run:243 reserve RPCs,47 close RPCs, peak32 concurrent
controller requests,18 intentionally lost charged-grant replies,3.312s credit
phase. Jitter was deterministic50..150ms; every13th reserve reply was lost after
commit, every7th close failed before commit and every5th close lost its ACK after
commit. Idempotent retry/recovery returned no credit twice. Total fixture21.50s;
PostgreSQL was capped at one CPU/768MiB. Fixtures cap runtime and RPC/data budgets.

The cold1MiB quota-path test at100ms delay improved from64 RPCs/1.29Mbit/s to
7 RPCs/11.79Mbit/s with demand-sized initial credit. The16MiB test used12 RPCs
(0.75/MiB),110.11Mbit/s at100ms and44.44Mbit/s at250ms. These measure quota-path
overhead only. Separate real two-node engine/TLS/broker/PG runs forwarded exact
103 and16,777,216 bytes each at250ms: Naive34.27Mbit/s, TrustTunnel/H2 36.22Mbit/s
on the shared build host. Do not extrapolate this to production WAN speed.

## Real packet loss and jitter

ops/run-hard-quota-netem.sh ran the actual native H2/H3 TCP/UDP gate in a private
--network none namespace,20±10ms jitter and1% loss, seed42. Kernel counters showed
871 packets/190,290 bytes and8 actual drops. Result PASS in4.429s: TCP authorized
103; actual upload and download103 each; whole UDP denied when short; both UDP
directions charged; broker disappearance failed closed. No host qdisc/sysctl or
Jakarta changes. Runtime test cap45s, tooling build cap90s, one CPU/256MiB.
Under loss the fixture separately reports authorized-versus-delivered cost;
uncertain engine-issued residue is never treated as refundable unused credit.

## Checks and remaining operational scope

Full backend/node Go suites and focused broker race checks pass. PostgreSQL
checks include32 concurrent duplicate closes, conflicting/foreign-node/boot/client
closes, Premium/free separation, original-month isolation and closed replay.
A concurrent grant/close test exercised1,601 engine-model byte grants with lost
ACKs and failed acquisition responses without double return/spend. Normal native
exact-boundary acceptance remains strict; loss mode never relaxes the ceiling.

Source/artifact hashes, logs and CI run are recorded in the final packet.
Production remains OFF. The technical owner still qualifies the reviewed actual
cohort's complete primary/fallback/private route inventory, fresh real runtime
capabilities, all-worker139 readiness, final legacy-counter reconciliation,
quiescence and rollback plan. No broad activation is authorized by these tests.
Residual crash/drain-timeout loss remains conservative: unknown cache, unresolved
funding or engine-issued bytes may stay charged. Keep tombstones/ledger on any
rollback and quiesce the cohort before downgrading; never refund uncertain residue.
