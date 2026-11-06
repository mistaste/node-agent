# Independent quota rollout expiry

This is the host-side fail-closed part of a coordinated quota rollout. It is
not an activation command or a fleet rollback coordinator. Importing the modules
does nothing. No production guard has been installed by the tests.

`barrier.py` renders a uniquely owned inet table for the actual inventoried
native ingress ports. It blocks new and established IPv4/IPv6 TCP/UDP before
conntrack/DNAT and covers local cached listeners. Only locally addressed data
ingress is selected; unrelated transit/outbound traffic and management/counter
ports are preserved. The actual kernel JSON must match the exact structural
policy before a barrier can be reported verified. Duplicate ports, management
ports and noncanonical scope identifiers are rejected.

`guard.py` closes that barrier before collecting two private native snapshots
at least 30 seconds apart. It then stops only four full container IDs with the
exact reviewed image, scope, project and service labels. Engines stop before
the credit broker, allowing normal known-unused settlement. The agent stops
last. Counter failures, disk exhaustion and an individual Docker failure do
not skip the other stop actions. Actual stopped/PID-zero verification is
required. A foreign or changed container is preserved and closure is unconfirmed.

Every invocation retains a new attempt directory. Native snapshots may contain
profile identifiers and must remain private, root-owned and mode 0600. Stable
JSON is deliberately conservative and is not proof that the normal pusher has
committed final source-separated counters to the database. A coordinator must
independently join those final counters, process known-unused closes and retain
all unknown issued credit before any accounting boundary changes.

The helper has no operation to change account flags, restore legacy engines,
remove the barrier, extend a deadline or authorize rollback. Even successful
closure explicitly requires coordinator review. A host without a complete
receipt cannot authorize reopening fleet ingress.

For a reviewed deployment, stage sealed helpers and a private manifest beneath
`/var/lib/guardex-quota-fleet/<canonical UUID>/`. The manifest requires schema 1,
scope, fixed integer deadline, actual ingress ports, exact image digest, project
`guardex-qf-<UUID>` and all four exact new container IDs. Use the service names
`node-agent`, `trusttunnel-runner`, `transport-bundle-runner`, `quota-broker` and
label each with `guardex.quota.rollout.scope=<UUID>`. Seal `guard.py`, `barrier.py`
and `manifest.json` in the private `source.sha256` file. No human credentials,
private keys or account tokens belong in this manifest.

`--render-units <manifest>` only renders fixed-calendar systemd service/timer
sources. A qualified installer must verify and enable both the timer and the
service's boot activation, verify the actual timer deadline, and retain their
hashes before starting any new engine. Persistent calendar scheduling catches
a missed deadline; boot activation reapplies closure after an already-expired
guard, since an nft table itself does not survive reboot. Before the fixed
deadline that boot invocation exits without network changes. Explicit
`--expire <manifest>` permits early safe closure. There is no sliding heartbeat.

Remaining production prerequisites include a qualified installer/coordinator,
all-host actual ingress inventories, complete route and mandatory-engine ACKs,
normal-pusher database joins, durable per-service Compose/update compatibility,
ledger-preserving rollback rehearsal, and client quota-control acceptance.
Do not install these guards or activate global enforcement based only on the
tests below.

Mandatory entry nodes reject the generic per-node update API with HTTP 409.
Its arbitrary checkout and default Compose commands cannot qualify retained
overrides, controller-written mandatory state, native engines and the shared
accounting boundary together. This includes agent-only and binary downgrades:
an older controller can rewrite mandatory native state as legacy. Metrics-only
relays and legacy non-mandatory nodes keep their existing update behavior.
Deploy mandatory nodes through the coordinated guarded path after qualification;
do not clear the mandatory setting to make a generic update succeed.

`closure_gate.py`, `receipt_store.py` and `coordinator.py` implement only the
fresh closure-evidence collection layer. The TLS endpoint accepts the exact six
inventoried host IPs and distinct per-host bearer credentials, ignores forwarded
source headers, bounds connections/bodies, and validates actual nft structure
and exact stopped container identities. Receipt sequences cannot be replayed to
refresh liveness; newer running/unknown state revokes a previous positive. Disk
failure also removes that host from the in-memory consensus. Counter files must
match the same operation, deadline, stopped IDs, dwell time and retained digest.
They still need independent schema validation and normal-pusher database joins.

Accepted receipts are private, append-only, fsynced records. Native snapshots
are content-addressed and deduplicated without removing history. Altered files
are never overwritten. An expired receipt is not live consensus, even if its
HTTP request is retried successfully. The API has no open, flag-change or
rollback-authorize route: both authority fields always remain false. Production
configuration binds only an owned primary high port, uses a private existing
TLS key on that host, and preserves the fixed operation window. No host reporter,
fleet activation/rollback coordinator or production installer is supplied by
this collection layer yet. Do not substitute its consensus for those remaining
accounting and routing prerequisites.

Validation:

```sh
python3 -m unittest discover -s ops/quota-fleet-guard -p test_guard.py -v
python3 -m unittest discover -s ops/quota-fleet-guard -p 'test_*.py' -v
timeout 45s unshare --net -- python3 ops/quota-fleet-guard/test_network.py --isolated
timeout 80s unshare --net -- python3 ops/quota-fleet-guard/test_expiry_runtime.py /private/new/evidence
timeout 30s unshare --net -- python3 ops/quota-fleet-guard/test_coordinator_network.py /private/new/evidence
```

The Linux tests require root and explicit disposable network namespaces.
The network acceptance exercises actual nft rules, existing/new flows,
IPv4/IPv6 TCP/UDP, loopback, management access and nonlocal egress. The expiry
acceptance creates only newly labelled, network-none sleep containers using
the pinned qualified image, verifies actual ID stops and foreign preservation,
then removes only those exact test fixtures. Their 120-second process lifetime
and the independent host timeout bound interruption cleanup. Production
container fingerprints and the host nft structure are checked separately.
