# Yandex API path repair

Fresh, fixed-IP TLS tests from the shared exit showed 10/12 failed TCP handshakes
to 37.230.168.172:443. Packet headers showed outgoing SYN retransmissions with no
incoming SYN-ACK on every captured failed flow. The same hostname, certificate
checks and IP passed 10/10 fresh connections from 82. This establishes the losing
exit-to-Yandex path; it does not identify the provider's packet-dropping device.

This independent scope selects only new WG TCP/443 connections from the five
qualified ingress addresses to the bounded public DNS address set for
`gateway.guardex-vpn.com`. HAProxy inspects the exact SNI and forwards that API
through 82. Every other SNI retains the original destination and port through
HAProxy's Linux original-destination support. TLS is never terminated here;
there is no HTTP inspection, credential handling or request replay.

The existing 82 stream listener emits PROXY protocol. Its new loopback-only
listener consumes that envelope and passes the original TLS bytes to Yandex,
without emitting PROXY protocol upstream. Public DNS and the configured primary
API hostname remain unchanged. Existing API routes, quotas and VPN exit guards
are untouched. No connection-tracking table is flushed.

## Qualification and installation

Run the nine local tests with
`python3 -m unittest discover -s ops/api-sni-yandex -p 'test_*.py'`.
On the exit, `qualify.py` creates three isolated namespaces. It tests strict TLS,
complete 256 KiB transfers, exact SNI matching, all five source peers, direct
listener denial, unrelated destinations, DNS-set changes, preservation of the
original destination and withdrawal. It removes its namespaces, interfaces,
processes and temporary test certificates before emitting `qualification.json`.

Install the exact reviewed source in the root-only directory
`/var/lib/guardex-yandex-api-path-20261127`, with `owner.json` identifying task
`guardex-yandex-api-path-20261127`. Existing HAProxy and loader hashes are pinned.
Do not change deployed source while an armed or retained scope uses its hashes.

On 82, `edge.py apply --expected-before-sha256 HASH` verifies the original stream
configuration and arms a 20-minute rollback before editing it. It validates and
gracefully reloads nginx. Verify fresh strict-TLS gateway responses and retained
COM/RU/Cedarport/probe behavior before proceeding.

On 94, run `controller.py arm`, then `controller.py apply`. Arming requires the
exact namespace qualification and a healthy strict-TLS 82 route. Application arms
an independent 15-minute rollback, installs a separate private listener, and adds
only this scope's INPUT chain and new-flow selector. The convergence timer checks
identity, health and DNS every 30 seconds. DNS changes update only the bounded
destination set, keeping previous addresses for ten minutes. Two consecutive
health failures withdraw new selection without stopping existing TLS streams.
Healthy convergence restores selection and only this scope's INPUT permissions.

## Retention and rollback

Before retention, require 20 fresh, strict-TLS successful API reads from each
ingress, zero failures, preservation of existing routes, and successful real
iPhone account/API/internet checks for all five countries. Save the actual
evidence as `acceptance.json`; never fill it from assumed results.
`controller.py retain` enables the independent service/timer and retires its
rollback. Then retain the edge after its 20 fresh TLS checks, using
`edge-acceptance.json` and `edge.py retain`. If either step fails, explicitly
back out the exit before the edge.

Use `controller.py backout` then `edge.py backout` for a retained rollback.
Unretained timers invoke `rollback` automatically, exit first. Identity checks
refuse to remove changed or foreign rules. The edge inverse removes only its
exact owned lines and preserves unrelated configuration edits.
