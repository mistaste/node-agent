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

Fleet-managed entry candidates also set `GUARDEX_QUOTA_FLEET_MANAGED=true`.
This keeps the generic update fence active in an optional-enforcement rollback
mode. Rollback must retain the qualified metering-capable native image: the old
Naive runtime lacks its server counter endpoint, while the audited rollback
authority deliberately ignores late client totals. An uncoordinated downgrade
could otherwise remove the only source of subsequent Naive usage. This flag
does not change quota eligibility, byte accounting or native enforcement mode.

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
TLS key on that host, and preserves the fixed operation window.

`reporter.py` collects only sanitized runtime identities and the actual owned
nft table. Observations are dated before the reads; missing commands and
timeouts report unknown state. A newer unfinished expiry attempt cannot reuse
an older counter file. Private sequence numbers survive restarts without
refreshing an earlier receipt. The sender binds the exact inventoried source
IP, connects directly to the primary, and verifies `api.guardex-vpn.com` with
normal OS certificate roots. It has no redirect, proxy, firewall, container or
account mutation operation. Settings and bearer credentials remain private.

The fleet activation/rollback coordinator and production installer are still
required. Do not substitute collection consensus for the remaining accounting
and routing prerequisites.

`counter_join.py` validates both native counter schemas and compares their
source-separated identities with database observations. It follows the normal
collector's TrustTunnel aggregation and rejects ambiguous Naive duplicates,
negative/overflow values, missing sources and nonexact counters. A greater DB
value cannot hide a native reset. A missing endpoint is never an empty array.
Matching raw counters alone do not prove quiescence, user attribution, daily
free/Premium accounting or credit settlement, and grant no mutation authority.

`compose_plan.py` renders an inert private plan from each service's own effective
Compose and actual Docker metadata. It preserves live commands, environment,
data paths and service-specific overrides, checks bind/capability ownership,
pins the qualified image and frozen source, and adds the shared owned broker
socket. Bounded candidates use `restart: no`; no build or dependency expansion
is permitted by the plan. Already-resolved dollar values are escaped for the
Compose interpolation pass. Use `command_environment()` for every Compose
invocation so bare unset live variables cannot import values from the CLI host.
Plans and normalized outputs contain credentials and must stay private on the
same host. Rendering/normalization is not installation, actual candidate runtime
equivalence, guard qualification or permission to activate accounting.

`source_archive.py` verifies the archive digest and Git commit comment before
extracting into a new canonical private directory. It rejects traversal, links,
special files, duplicate paths, conflicting parent files, Git metadata and
unbounded archives. Files and directories are durably synced; an existing tree
is never replaced. It does not create containers or install/arm a guard.

`stage.py --input <private JSON>` prepares only four stopped candidates from a
qualified plan and a fixed source/image/deadline. It requires the actual Linux
host namespace and local Docker socket, verifies the original live service
identities/configuration, and never builds, pulls, starts, arms or replaces a
public service. Mount list order and decimal memory representation are normalized
without relaxing path, permission or byte-limit equality. Actual candidate
environment, command, mounts, capabilities, resource policy, image and PID-zero
state must match before a sealed manifest and private rendered units are saved.

If creation completed but validation failed, retain that failure. The separate
`--finalize-stopped <scope> --expected-input-sha256 <original hash>` phase can
revalidate those exact existing resources and the byte-exact source tree, using
the original unchanged deadline. It creates no container and cannot overwrite
an existing or partial seal. Its new receipt does not rewrite the failed
attempt. Neither phase installs a timer, applies a barrier or authorizes opening
ingress/activating flags. The qualified arming/start/accounting state machine
is still required.

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
