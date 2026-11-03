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

This first implementation obtains a charged grant for every TCP chunk (max
16 KiB) or whole UDP payload, shared across both directions and all transports.
No unused balance survives a broker restart and no uncertain charge is refunded.
Measure throughput and control-plane capacity on the canary before fleet rollout.
A passed byte-boundary acceptance does not establish production throughput.

Acceptance evidence must identify actual binaries, source/patch hashes and flags.
The backend opt-in PostgreSQL acceptance can launch two real Caddy nodes and
brokers. Rust's hard_quota tests cover missing broker, partial TCP and atomic
UDP; real H2/H3 TCP/UDP acceptance is additionally required before rollout.
