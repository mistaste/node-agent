# Live monthly traffic quota

The backend manifest excludes every profile of an account whose current UTC
month's free usage has reached its effective allowance. This includes ordinary
primary/fallback bindings and private bootstrap grants. Active Premium bypasses
the free allowance. Profiles are retained: a new month, a current-month top-up
or Premium restores membership through normal reconciliation.

## Runtime enforcement

TrustTunnel must run the reviewed live-credentials ABI 1 endpoint and supporting
runner. Its existing credential epochs cancel only the removed user's active
TCP/datagram requests. A legacy endpoint is not proof of targeted revocation;
verify exact deployed image and endpoint SHA before enabling the backend filter.

Naive requires `forwardproxy-live-credentials.patch`, applied after the existing
account-QoS patch to forwardproxy commit
`d62c80d3dd2c706b6b87579844d2397bddd18317`, with Caddy 2.11.4.
The generated `guardex_credentials` app publishes SHA-256 hashes of accepted
Basic-auth tokens at Caddy app Start. Validation alone cannot publish membership.
A graceful reload closes only removed identities' CONNECT target sockets and
cancels their request contexts, including requests owned by old handler
configurations. New requests on old HTTP/2 transports also check current
membership. Unchanged users retain their existing streams. Startup failure
restores the previous live authority; already closed revoked flows stay closed.

Naive counts actual upstream socket reads/writes. Its loopback Caddy admin route
`GET /guardex/clients` exposes UUID, active flow count and cumulative bytes, never
passwords or Basic-auth tokens. Node metrics push these as source `naive`.
Backend persists `naive:<UUID>` counters separately from TrustTunnel, so a reset
of either runtime never re-charges the other's cumulative total. Both sources
still consume the same account quota. Naive UDP is not supported; UDP/datagrams
use TrustTunnel and its existing revocation path.

## Coordinated release order

1. Build and stage the supporting Caddy and TrustTunnel endpoint/runner artifacts.
   Verify a two-user canary on isolated loopback fixtures first.
2. Deploy the backend including migration `000136_live_traffic_quota` and source
   aware accounting **before** a node starts pushing `source: naive`. An old
   backend would combine the two independent streams under one counter key.
3. Release the node agent and Caddy together. Generated Caddyfiles require the
   new app/directive; an old Caddy must reject this configuration. Preserve the
   preceding exact image and configuration for rollback.
4. Coordinate one node at a time through the release queue. No global endpoint,
   inbound, topology or fleet restart is part of enforcing one user's quota.
   Verify actual binary provenance and the over-quota/unchanged-user isolation
   gate, then expand rollout. Mainline source tests are not fleet acceptance.
5. Client owners should render `free_traffic_limit_exceeded`, stop automatic
   reconnect loops and show the authoritative remaining quota/reset time.
   Native server enforcement does not depend on a client upgrade.

## Timing and limits

This is sampled server enforcement, not distributed byte reservation. Default
collection and push clocks are independently 15 seconds and manifest pulls are
30 seconds: healthy operation can take about 60 seconds plus request/apply time
from actual crossing to node removal. Bytes transferred in that interval can
exceed the nominal allowance; no fixed byte bound is promised. Controller outage
or failed apply can extend that delay. Once the new membership is applied,
existing flows are closed and cached credentials cannot continue forwarding.
An exact zero-byte overrun across concurrent servers would require a separate
reservation/lease design and fail-closed data-plane budgets.

## Source validation

Run `go test ./...` in node-agent and the focused race tests for metrics, pusher,
transportbundle and TrustTunnel runner. Docker's caddy-naive stage runs the new
isolated live-credential suite before building the Caddy executable:

```sh
GO_TEST_RACE=1 sh ops/test-forwardproxy-live-credentials.sh /path/to/patched/forwardproxy
```

The suite uses real loopback Caddy HTTP/1 and HTTP/2 CONNECT streams for two
synthetic users. It verifies targeted close, unchanged original streams,
reconnect denial, membership restoration, invalid-config isolation, cumulative
traffic across reload and the Caddyfile adapter. It avoids upstream TestMain,
which starts unrelated fixed-port services and writes an autosaved config.
No production credentials, listeners or database are used by this suite.
