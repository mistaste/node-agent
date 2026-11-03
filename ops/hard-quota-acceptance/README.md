# Native TrustTunnel byte-boundary acceptance

Run from this directory with an absolute path to the freshly built native binary:

```sh
GUARDEX_TT_HARD_TEST_BINARY=/absolute/path/trusttunnel_endpoint go run .
```

The fixture generates its own certificate and credentials, binds only loopback
TCP/UDP and a private temporary Unix socket, then starts the actual endpoint with
mandatory enforcement. Its deterministic in-process broker gives the H2/H3
flows one shared 103-byte allowance. It verifies exact TCP upload and download
boundaries, whole-datagram refusal, UDP upload/download accounting and broker-loss
fail-closed behavior. The endpoint is stopped and temporary files removed.

This fixture isolates the native engine gate. It does not replace the backend
PostgreSQL concurrency test or the real broker/TLS-controller acceptance. Run on
an isolated host or a disposable network namespace, never a production endpoint.

The operational network mode is run by ops/run-hard-quota-netem.sh in a private
Linux network namespace:20±10ms jitter,1% loss with seed42, max45s, one CPU/256MiB.
It keeps the authorization ceiling strict but reports authorized-versus-delivered
TCP bytes separately because lost/uncertain engine-issued bytes cannot be refunded.
UDP may retry within an explicitly larger bounded test budget; each datagram
still needs its full credit. Normal mode still requires exact103-byte delivery.
The disposable tooling image build is capped at90s; no host qdisc/sysctl changes.
