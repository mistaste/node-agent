# Batched quota credit: isolated latency acceptance

Historical migration138 speed-only packet. Operational qualification found
material unused-credit cost and superseded this with migration139 known-unused
closes and demand-sized initial credit. Use HARD-QUOTA-OPERATIONAL-RESULTS.md and
the current rollout runbook; do not activate the138 no-return policy.

The original pre-forward broker (1922ce2) performs one verified TLS controller
request per 16 KiB. Its opt-in quota-path test measured 64 RPCs/MiB and 1.29 Mbit/s
for a cold 1 MiB transfer with an added 100 ms controller response delay. This is
a real transport bottleneck even when the payload network is otherwise idle.

The batched broker charges central credit first, then spends that credit locally
under a per-credential lock shared across streams and directions. Sustained
traffic grows requests from 64 KiB to 4 MiB; each reservation keeps its own
original deadline, clamped to a monotonic maximum of five seconds. It does not
extend a lease, persist credit, refund uncertain bytes or permit partial UDP.
Repeated denials are coalesced for 250 ms; this can only delay retry, never permit
forwarding. Cached credit can outlive controller availability only until its
original expiry because those bytes are already charged.

Measured on 2026-11-03:

| Path | Injected delay | Payload | RPCs | RPCs/MiB | Mbit/s |
| --- | --- | --- | --- | --- | --- |
| Original quota RPC path, cold | 100 ms | 1 MiB | 64 | 64.000 | 1.29 |
| Batched quota RPC path, cold | 100 ms | 1 MiB | 5 | 5.000 | 16.44 |
| Batched quota RPC path | 100 ms | 16 MiB | 10 | 0.625 | 131.42 |
| Real Naive H1/H2, two nodes/eight streams, TLS brokers/PostgreSQL | 100 ms | 16 MiB | 17 | 1.062 | 81.22 |
| Real TrustTunnel H2, two nodes/eight streams, TLS brokers/PostgreSQL | 100 ms | 16 MiB | 17 | 1.062 | 57.68 |
| Batched quota RPC path | 250 ms | 16 MiB | 10 | 0.625 | 53.31 |
| Real Naive H1/H2, two nodes/eight streams, TLS brokers/PostgreSQL | 250 ms | 16 MiB | 17 | 1.062 | 46.35 |
| Real TrustTunnel H2, two nodes/eight streams, TLS brokers/PostgreSQL | 250 ms | 16 MiB | 17 | 1.062 | 34.04 |

The final 250 ms runs include the server-relative remaining-TTL hardening;
the earlier 100 ms runs preceded that wire addition. Both real-engine runs also tested an exact 103-byte boundary. Their sinks
received exactly the shared account allowance, including on the larger 16 MiB
runs. RPC totals include cold-start growth and terminal denials; steady-state
reservation granularity is 4 MiB. Native H2/H3 TCP/UDP engine gates are unchanged
and retain the prior native byte-boundary acceptance.

Reproduce the TLS-only quota-path test:

```sh
GUARDEX_QUOTA_LATENCY_BENCH=1 go test ./internal/hardquota \
  -run '^TestControllerRTTBenchmark$' -v -count=1
```

For the full engine path use the backend's isolated
TestHardQuotaConcurrentPostgres with GUARDEX_QUOTA_CADDY_TEST_BINARY,
GUARDEX_QUOTA_TT_TEST_BINARY and GUARDEX_QUOTA_BROKER_TEST_BINARY. It requires the
explicit disposable database DSN and never uses production configuration.

These are fixed injected RPC-delay tests over loopback payload sockets, not a
production WAN speed claim. Read-only health probes to the configured public controller origin returned HTTP
200 with total fresh-TLS times of 263-728 ms; one sample separated 4 ms DNS,
51 ms TCP connect and 124 ms additional TLS setup. These vary by route and are
not a measured authenticated reservation RTT. The 100/250 ms injected envelope
exercises nonzero controller latency without loading production accounting.
The PostgreSQL container was capped at one CPU;
shared build-host load varies. Actual route jitter/loss, many-account capacity,
steady-state client workload and the cost of unused charged credit still need
canary observation. Backend migration 138 must precede the batched broker.
Production hard quota remains disabled until the canary rollout owner validates
that scope; this change authorizes no fleet enablement or global restart.

The batched broker requires the updated API's `valid_for_ms`, recomputed from the
original grant expiry using the database clock on every response/retry. It anchors
that remaining lifetime before the RPC using local monotonic time and a safety
margin. Node wall-clock skew cannot extend a month/Premium deadline. Missing or
out-of-range remaining TTL fails closed; deploy the API before this broker.
