# Strict traffic quota rollout

Production remains OFF until the bounded cohort owner qualifies all routes.
Deploy the backend API and migrations through **139 on every API worker first**,
then the updated broker and patched engines. New funding responses must contain
`settlement_version=1` and server-recomputed `valid_for_ms`; missing/old/mixed
protocol responses cannot fund engine traffic. Both engine runners still require
GUARDEX_HARD_QUOTA_REQUIRED=true and a real mandatory-runtime acknowledgement
before advertising hard_quota_version=1. The backend account gate defaults false.

The broker uses existing CONTROLLER_URL, AGENT_SECRET and INTERNAL_SERVICE_TOKEN
with verified HTTPS, plus a root:65532 mode0660 private Unix socket shared only
with the engine runners. Initial credit is demand-sized; sustained traffic grows
reservations up to4MiB. All credit is charged centrally before engine grants and
shared across streams/directions of a credential. Each reservation retains its
own original <=5-second deadline, anchored before RPC on local monotonic time.
Refill/retry cannot extend a month/Premium expiry. UDP is all-or-nothing.

## Known-unused closes

Only bytes irrevocably detached by the broker before being handed to an engine
can return. POST /v1/internal/node/traffic/settle is bound to original server,
request, boot, client, account and period. Its transaction/advisory lock records
an immutable settlement tombstone and refunds once; repeated identical closes
acknowledge without another refund, conflicting closes fail, and closed-reserve
replay returns zero/TTL0. Old-period returns never fund the current period.

The broker sweeps expired known-unused credit and drains it on graceful stop.
Lost close acknowledgements retain the immutable close for retry. Failed funding
requests are retried/recovered using the SAME original request identity; results
never handed to an engine are closed, not made spendable during recovery. There
is no server-side automatic expiry refund and no persisted/recreated credit.
Engine-issued bytes with uncertain delivery and cache lost in a crash remain
charged. The measured crash residual is explicit in the operational results.

During controller outage only previously charged, unexpired credit can be used;
refill is fail closed. Broker loss stops new engine grants. Repeated denials are
coalesced for250ms and can only delay retry, never permit forwarding. Pending
close/recovery state is bounded; it is not spendable credit.

## Bounded handover

Run `python3 ops/audit-udp443-redirect.py` on each ingress host before physical
acceptance or activation. It compares native nft predicates with the ordered
iptables projection and fails on a catch-all UDP redirect or unknown semantics.
An iptables-save projection can omit the native `udp dport 443` expression;
deleting every apparently broad text line can therefore remove a correct rule.
Repair only a proven native catch-all handle under a bounded rollback guard,
retain the actual UDP443 rule, and verify both a non443 H3 transfer and public443
strict QUIC/TLS. Preserve process IDs, counters and unrelated rules. Also inspect
the persisted rules file: its owned redirect must explicitly match UDP443 and
pass `iptables-restore --test` without reloading the live firewall.

Reconcile final legacy counters; quiesce every primary, fallback and private route
before ledger handoff. Old engines cannot reconstruct historical unreported
traffic. Confirm real compatible runtime ACK/capability freshness and all API
workers' settlement support, then use the backend checked activation SQL for the
reviewed cohort. Never expose an enabled account on an unmetered route. Any
rollback must first quiesce the cohort and stop brokers; retain settlement
tombstones and ledger state. Do not erase/refund unknown credit or reactivate
legacy routes while the account can still forward traffic.

Evidence must identify exact source, binaries, route/cohort scope and accounting
cost. The quota-only latency benchmark is opt-in in internal/hardquota. The
backend opt-in PostgreSQL canary covers real brokers/TLS/DB,32 concurrent accounts
with deterministic jitter/lost replies, low-volume/pause/expiry/graceful/crash
cost, plus separate real-engine byte-ceiling tests. ops/run-hard-quota-netem.sh
runs native H2/H3 TCP/UDP in a disposable --network none namespace with jitter
and packet loss; it changes no host qdisc/sysctl. See the operational results.
