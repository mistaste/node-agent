# TrustTunnel endpoint 1.1.0 rollout

The node image pins the official stable `v1.1.0` release at commit
`fab5b8353a19332f935fa30869307d37d4a898d1`.

Pinned release archive digests:

- Linux x86_64: `91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7`
- Linux aarch64: `c2aee17a1ced349283cba4775202e2baba053b8ea835d4cc23dc67d16c6b9686`

The release fixes UDP timeout socket cleanup, global IPv6 classification and
reverse-proxy access to a configured private origin. Optional per-client
metrics remain disabled unless explicitly configured on a protected listener.

For each node, verify the release archive digest, run the new binary once in
an isolated container with no published ports, then derive a canary image from
the exact currently deployed image with `Dockerfile.trusttunnel-canary`.
Append `docker-compose.trusttunnel-canary.yml` to the normal Compose files and
recreate only `trusttunnel-runner` with `--no-deps`.

After every node verify the reported version, container state, HTTP/2 and
HTTP/3 managed listeners, controller freshness and client egress. Keep the
previous image ID locally until rollback consists of recreating only
`trusttunnel-runner` with that image. Never restart the other node services as
part of this endpoint-only update.
