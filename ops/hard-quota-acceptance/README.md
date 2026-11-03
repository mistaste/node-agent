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
