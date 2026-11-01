# Naive idle streams and transport evidence

## Verified deployment inventory (2026-11-01)

All eight active nodes reported Caddy v2.11.4: DE-FRA-FREE-1,
FI-HEL-PREM-1, ID-JAK-PREM-1, NL-DRO-FREE-1, NL-EYG-EXIT-1,
PL-WRO-PREM-1, RU-MOW-RELAY-1 and US-WIL-PREM-1. Separate transport runners
where present reported the same version. No live configuration was changed.

Caddy 2.11.6 introduced default one-minute body-read/write idle timeouts and
regressions affecting quiet streams. 2.11.7 fixes those stream regressions.
Sources: https://github.com/caddyserver/caddy/releases/tag/v2.11.7 and
https://caddyserver.com/docs/caddyfile/options#timeouts.

The current 2.11.4 pin does not support the new Caddyfile directives. Do not add
read_body_idle/write_idle to it. The version gate blocks 2.11.6, unreviewed
upgrades and unsupported directives. When upgrading, review version, defaults,
plugin compatibility and timeout config together. Negative durations disable
the new idle timers only on compatible versions; keep header/handshake/resource
limits. A timeout config change is conditional on this compatibility review.

## Real-binary idle acceptance

Build `go build ./cmd/naive-idle-check`, then run:

```
./naive-idle-check -caddy /absolute/path/to/caddy -idle 90s,180s,300s
```

The test launches an independent Caddy on ephemeral loopback ports with its
forward_proxy module and default timeout policy. It concurrently verifies:

- an established HTTP/2 CONNECT tunnel resumes duplex exchange after each pause;
- a certificate-verified inner TLS/SSE response resumes after each quiet period;
- caller cancellation promptly closes the origin connection.

All traffic is synthetic. No production credentials, public listener, system
config, route or firewall changes are involved. Full windows run concurrently
in about five minutes. A failed scenario returns nonzero and its failed phase.
This is Caddy HTTP/2 CONNECT acceptance, not full Naive padding/client, HAProxy,
mobile handover, or end-to-end physical-network certification.

Release CI runs the test against the newly built runtime image without external
network/capabilities, before signing, attestation or guarded rollout. The JSONL
results and probe checksum are included in release artifacts. The image can be
present in the registry unsigned if acceptance fails; it is not rolled out.
Do not trigger the release workflow merely to test these changes: it publishes
and may invoke the configured rollout webhook.

## Separate failure phases

```
go run ./cmd/transport-diagnose -url https://api.guardex-vpn.com/health
```

The GET probe reports DNS, TCP, TLS, HTTP-header waiting and HTTP status, with
elapsed time. TLS trust remains enabled; redirects and environment HTTP proxies
are disabled so this diagnoses the direct route. No URL, IP, response body,
headers, token or raw error message is written. Credential/query-bearing URLs
are rejected. DNS/TCP/TLS errors, header deadlines, certificate failures and
caller cancellation remain distinct. HTTP5xx is server_error, not DNS failure.
Existing mobile ApiNetworkProbe already records separate DNS/TCP/TLS/HTTP
phases and suppresses probe events after cancellation; it was left untouched.

Idle-resume failures are identified by the acceptance scenario, not guessed
from a generic production timeout. A successful transition followed by ordinary
request recovery needs client timeline evidence; never infer recovery merely
from TCP keepalive or a later unrelated health check.

## Synchronized client/server evidence for a reproducible incident

Use one affected client and one owned node. Record UTC time, protocol and exact
pause duration, and confirm clock synchronization on both sides. Do not label
TLS failure as filtering solely because TCP connects or traceroute shows stars.
Collect the same short time window at both endpoints, using the peer address
visible at each endpoint (NAT can change the tuple):

```
python3 ops/capture_transport_evidence.py --peer PEER_IP --port 443 --seconds 30 --output private.pcap
python3 ops/summarize_transport_capture.py private.pcap --peer PEER_IP
```

The capture requires existing capture privileges and tcpdump. It neither adds
privileges nor changes interfaces, services, routes or firewall rules. It limits
capture to one peer/port, 60 seconds maximum, 2,000 packets, 128-byte snapshots,
and a newly created mode0600 file. On macOS choose an actual interface instead
of Linux `any`. Captures still contain private addressing and truncated TLS
metadata; retain locally and do not upload them automatically. Stop at a SYN,
FIN/RST, retransmission and ClientHello/ServerHello metadata comparison; use
larger/full captures only with a separate explicit scope. Truncation may make
TLS handshake dissection incomplete, so missing handshake counts are not proof
of packet loss.

The optional tshark summarizer prints direction/counts only, not addresses or
payload. Compare: did the ClientHello reach the node, did ServerHello leave,
which side sent FIN/RST, and where retransmissions begin? Compare independent
networks before attributing an outage to an operator, MTU, filtering or a node.
The Habr case describes evidence gathering, not proof that our failures have
the same cause: https://habr.com/ru/companies/habr_moneta/articles/1091260/.

No real-incident customer traffic capture was started as part of the baseline
inventory: the isolated acceptance fixture is separate from live VPN traffic.

## Baseline result

All seven scenarios passed using the existing production image's Caddy binary
in an isolated network-none container: duplex and quiet TLS streams at 90,
180 and 300 seconds, plus cancellation cleanup. See
`naive-idle-baseline-20261101.json`. Full Go race suite, the negative idle-reset
fixture, go vet for new packages and seven Python tests passed. The direct API
health probe completed DNS/TCP/TLS/HTTP with HTTP200. Temporary test container
and remote test binary were removed. Changes remain in the isolated local
worktree; no signed release, registry publication or rollout was triggered.
