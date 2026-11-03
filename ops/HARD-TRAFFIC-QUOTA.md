# Strict traffic quota rollout

Build the updated image containing `quota-broker`, the patched Caddy module and
TrustTunnel `1.1.0-guardex-hard-quota.1`. The broker uses the existing
CONTROLLER_URL, AGENT_SECRET and INTERNAL_SERVICE_TOKEN from `.env`; controller
HTTPS verification is mandatory. The shared Unix socket is root:65532 mode 0660
inside a private directory, mounted only into the broker and engine runners.

Deploy the backend migration 137 and reservation API before activating engines.
Set GUARDEX_HARD_QUOTA_REQUIRED=true on a canary node's node-agent configuration
and recreate the updated services. Both engines must acknowledge mandatory quota
before hard_quota_version=1 is advertised. Unsupported binaries cannot satisfy
the mandatory state. Activation restarts existing unmetered TrustTunnel children;
the Caddy credential app closes old unmetered CONNECT handler generations.

The account flag in the backend is a separate handover gate. Until it is enabled,
mandatory engines deny data for the account. Enable only after every primary,
fallback and private route has a fresh hard_quota_version=1 report and the final
legacy counters have been reconciled. Use the backend's checked activation SQL.
Never downgrade an enabled account onto an unmetered route. Broker/controller
loss deliberately interrupts forwarding; there is no fail-open fallback.

The broker reserves byte credit centrally before making it available to engines.
Credit is shared by all streams and directions of a credential; reservations grow
from 64 KiB to at most 4 MiB during sustained demand. Each reservation retains its
own original deadline (at most five seconds, and bounded by entitlement/month
expiry). A refill never extends an older reservation. Cached credit is memory
only; lost replies, process restart and expiry never refund or restore it. UDP
needs the complete datagram budget before any payload is forwarded.

Deploy backend migration 138 before the batched broker. During a controller
outage only previously charged, unexpired credit can still be used; refill is
fail closed and expiry stops cached credit. Broker disappearance stops the data
plane immediately. Idle/lost unused credit remains charged: the conservative
maximum outstanding reservation is 4 MiB plus a residual payload per active
credential per node. Unused expiry charges can accumulate over repeated bursts; compare charged
ledger bytes with actual free-traffic counters after drain during canary monitoring.
This is a conservative quota tradeoff, not a claim of exact payload-only billing.

The opt-in latency benchmark is in internal/hardquota/latency_benchmark_test.go.
Run GUARDEX_QUOTA_LATENCY_BENCH=1 go test ./internal/hardquota -run
TestControllerRTTBenchmark -v. It measures quota-path overhead with injected TLS
controller delay, not production VPN throughput. Backend acceptance additionally
measures real engine/broker/TLS/PostgreSQL forwarding at injected 100/250 ms delay.
Keep fleet enablement off until representative canary capacity is verified.

Acceptance evidence must identify actual binaries, source/patch hashes and flags.
The backend opt-in PostgreSQL acceptance can launch two real Caddy nodes and
brokers. Rust's hard_quota tests cover missing broker, partial TCP and atomic
UDP; real H2/H3 TCP/UDP acceptance is additionally required before rollout.

The batched broker requires the updated API's `valid_for_ms`, recomputed from the
original grant expiry using the database clock on every response/retry. It anchors
that remaining lifetime before the RPC using local monotonic time and a safety
margin. Node wall-clock skew cannot extend a month/Premium deadline. Missing or
out-of-range remaining TTL fails closed; deploy the API before this broker.
