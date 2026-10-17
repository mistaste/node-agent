# TrustTunnel live credential updates

An ordinary profile membership change used to alter the endpoint process key,
stopping every active connection on that endpoint. TrustTunnel v1.1.0 loads its
credential registry and connection limits once at startup; ignoring changes or
sending its TLS-only SIGHUP is insufficient.

The reviewed endpoint remains based on upstream commit
`fab5b8353a19332f935fa30869307d37d4a898d1`. It retains Guardex's UDP rejection fix
and adds credential reload ABI 1. Source pins and ordered patch hashes are in
`patches/trusttunnel-live-credentials-manifest.json`. Its reported version is
`1.1.0-guardex-live-credentials.1`.

With `GUARDEX_CREDENTIALS_ACK_FILE` set by the runner, the endpoint polls the
atomically replaced credentials file. It validates the complete file before
replacing the authentication registry and connection limits, preserving live
counters and unchanged credential epochs. Removing credentials cancels only
their active TCP/datagram requests; inherited SNI authentication is rechecked
for subsequent requests. Invalid, empty or duplicate credentials retain the
last valid registry and do not receive an acknowledgement. The agent renders
a disabled sentinel when there are no active users.

The endpoint publishes the SHA-256 of the exact applied credential bytes. The
runner acknowledges a membership update only after the endpoint reports that
digest and remains running. Legacy split H2/H3 configurations require both
endpoint acknowledgements. Static configuration changes still restart the
endpoint. The runner advertises ABI support only for the reviewed binary
version; an older binary cannot silently accept a skipped restart.

The agent's live-update path requires an already healthy supporting runner and
unchanged identity, ports, TLS hosts and endpoint settings. It writes only
credentials and durable state, waits for the runner acknowledgement, and
restores the previous bundle on failure. An unacknowledged change is never
reported as successfully applied. Neither the binary nor runner prints
credentials or their configuration contents.

The runner's configured default interval of 250 ms is now honored. The previous
parser rejected it because its minimum was 500 ms and silently substituted two
seconds, adding unnecessary reconciliation latency.

## Validation

`go test ./...` and `go test -race ./internal/trusttunnel ./cmd/trusttunnel-runner`
cover live publication, unchanged process identity, missing acknowledgement,
rollback, permission boundaries and interval parsing.

The pinned endpoint passed its full workspace suite locally; production library
and executable Clippy checks pass. Linux/musl passes 94 library tests, the two
H2/H3 live-flow integration gates and the malformed credential parser test.
The H2/H3 gates keep Alice's stream open while adding and removing Bob, verify
that Bob can authenticate after addition, then require Bob's existing stream
to close after removal while Alice's original stream continues.

Run the actual runner/binary gate on an isolated Linux build host:

```sh
python3 ops/test_live_credentials_endpoint.py --binary /absolute/path/to/trusttunnel_endpoint --runner /absolute/path/to/trusttunnel-runner
```

It uses synthetic loopback-only accounts and certificates, verifies 8 MiB
through the same Alice connection across addition, malformed replacement and
revocation, checks rejection of revoked credentials and requires the endpoint
PID to remain unchanged. It starts no production service and removes its own
temporary files and processes.

Before rollout, validate the static executable inside the exact deployed Alpine
image with no production mounts, no network, dropped capabilities and a read-only
root. Build binary-only overlays of each exact running image. Stage both the
runner and endpoint together; update the agent only after the supporting runner
is healthy. Keep original image IDs and Compose configuration for rollback.
Canary one node, verify controller freshness and real egress, and roll remaining
nodes individually. Do not restart topology-agent or transport-bundle-runner.
