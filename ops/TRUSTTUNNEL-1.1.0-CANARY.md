# TrustTunnel endpoint 1.1.0 canary

The node image pins the official TrustTunnel endpoint `v1.1.0` release.
The release tag resolves to commit
`fab5b8353a19332f935fa30869307d37d4a898d1`.

Pinned release archive digests:

- Linux x86_64:
  `91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7`
- Linux aarch64:
  `c2aee17a1ced349283cba4775202e2baba053b8ea835d4cc23dc67d16c6b9686`

The release corrects UDP timeout socket cleanup, global IPv6 address
classification, and reverse-proxy access to a configured private origin. Its
optional per-client metrics remain disabled unless the protected metrics
listener is explicitly configured for them.

Before the first deployment, run the new binary in a separate container with
the node's existing TrustTunnel configuration mounted read-only. Do not publish
ports from that container. A successful five-second run proves that the
configuration is accepted without touching the live endpoint.

For the first live canary, build `Dockerfile.trusttunnel-canary` from a context
containing only that verified binary. Pass the exact currently deployed image
tag as `BASE_IMAGE`. This keeps every other binary and package byte-for-byte
identical to the previous node image.

Set `TRUSTTUNNEL_CANARY_IMAGE` to the locally built immutable canary tag and
append `docker-compose.trusttunnel-canary.yml` after the normal Compose files.
Recreate only `trusttunnel-runner` with `--no-deps`.

Roll out to one node first. Record the previous image ID and keep it locally,
replace only `trusttunnel-runner`, then verify:

1. the endpoint reports version `1.1.0`;
2. both HTTP/2 and HTTP/3 managed listeners are reachable;
3. the node controller and transport bundle are current;
4. an existing `1.0.49` mobile client can connect, pass an egress check, and
   recover across a network transition;
5. container restarts and UDP socket counts remain bounded.

Rollback consists of restoring the previous image for
`trusttunnel-runner` and recreating only that service. Other node services and
the public TCP proxy must not be restarted.
