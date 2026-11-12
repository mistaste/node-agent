# HTTP/3 response finalization

An unanswered or credit-blocked CONNECT response could be dropped before its
HEADERS were committed. The endpoint sent a zero-byte FIN. On the physical iOS
client, nghttp3 received `input_bytes=0, fin=true` while still in `RESP_INITIAL`,
with no status code. Its `H3_FRAME_UNEXPECTED` error then retired the entire
connection, disrupting unrelated streams. Do not suppress that parser error.

The codec now shares response-header commitment with its write shutdown path.
Before commitment it sends RESET_STREAM with H3_REQUEST_CANCELLED; after
commitment it preserves queued response bytes and sends FIN. The package also
includes the previously tested HTTP/3 lock-order, pending-frame capacity, and
blocked-header capacity-growth fixes needed by this production baseline.

Late readable notifications for a locally cancelled request also used to escape
as a connection error. The codec now retires that request's read half and
discards pending request data without closing sibling streams. Genuine socket
and parser failures still propagate.

When the peer finishes its request with a bare FIN, a reader already waiting for
data must also be woken. The codec now notifies that reader before retiring the
read half; a response can still be written after the request EOF.

The baseline directory contains exact, digest-verified build inputs read from
the deployed Finland node. They preserve live credential reload, UDP rejection,
account quotas and the vendored HTTP/2 capacity correction. No credential or
runtime configuration is included. The source commit and compiler image are
pinned in `manifest.json` and the build recipe.

The deployed binaries differ from those source inputs: five original nodes did
not contain the account-QoS capability, while Poland did. This replacement
contains it on every node, but it is inactive unless the endpoint receives
`GUARDEX_ACCOUNT_QOS_SOCKET`. Actual process environments have that setting only
in Poland; deriving each overlay from its own current image preserves the
activation policy. Source files and shared image tags alone do not prove the
contents of a running binary.

## Build and deploy

Run from the repository root with an empty, private output directory:

```sh
python3 ops/trusttunnel-http3-response-finalization/verify_inputs.py
docker buildx build --platform linux/amd64 \
  -f ops/trusttunnel-http3-response-finalization/Dockerfile.endpoint \
  --output type=local,dest=/absolute/private/endpoint-output .
```

The existing production build helper tests the Linux endpoint library and live
credential reload, builds the binary and rejects a dynamic ELF interpreter.
The pinned build helper uses `1.1.0-guardex-account-qos.1`; identify this
correction by the binary SHA-256 and overlay image digest rather than the
version string.
BuildKit caches compiler outputs without changing the pinned source, compiler,
test commands or static-binary checks. An empty cache supports the same build.

For each node, derive an overlay from that node's exact deployed image digest
using `Dockerfile.overlay` and a context containing only the verified binary.
Retain the old image and compose configuration. Recreate only
`trusttunnel-runner`, verify health, credentials, quota enforcement and physical
HTTP/2/HTTP/3 traffic, then proceed to the next node. Other node services and
quota limits are outside this change. Roll back by restoring the prior image
and recreating the same service.

### Guarded rolling operations

`guarded_rollout.py` performs one node operation at a time. Supply a private,
reviewed inventory containing each node's actual image ID, endpoint digest,
original Compose file digests and the seven baseline source-file digests. Keep
the successful Linux build receipt alongside the binary. A shared image tag or
source tree does not replace an actual running-image or `/proc/.../exe` check.

```sh
python3 ops/trusttunnel-http3-response-finalization/guarded_rollout.py \
  --pins /absolute/private/rollout-pins.json --node NODE-CODE \
  --binary /absolute/private/endpoint-output/trusttunnel_endpoint \
  --receipt /absolute/private/linux-build-receipt.json \
  --operation unique-reviewed-operation --mode preflight
```

The default `plan` and `preflight` modes do not recreate containers. Reuse the
same arguments with `--mode apply` only after reviewing the preflight. The helper
builds an overlay from that node's exact original image, appends one uniquely
owned Compose file and recreates only `trusttunnel-runner`, without dependencies,
builds or pulls. Physical route, digest, throughput and cleanup checks remain
operator gates between nodes; a successful deploy receipt is not mobile release
acceptance.

Before any recreation, the helper retains the complete original Docker inspect
on the node under a root-owned `0700` operation directory, with `0600` files. That
inspect contains credentials: never copy it into the Docker build context,
download it into a report or print its raw environment. Original Compose files
and journals remain immutable. Only the binary and overlay Dockerfile enter the
image build context.

Runtime checks preserve the complete Config, HostConfig and mount records.
Only the owned image, generated hostname and exact owned Compose metadata
transition are exempted. Unique environment keys are compared as a lossless map;
duplicates, malformed entries and changed values are rejected. DNS empty lists
remain distinct from `null` in the fingerprint. When the original Docker runtime
has exact empty `DnsOptions` or `DnsSearch`, the owned override explicitly supplies
`dns_opt: []` or `dns_search: []` so current Compose preserves that representation.

The original integer `NanoCpus` is converted with `Decimal`, without a floating
point round trip, and retained in both new-image and rollback overrides. An
existing Compose deploy CPU limit is set to that same exact value. The resolved
Compose CPU model is checked before any recreation. This prevents a manual
runtime constraint from reverting to a stale Compose default: the Poland rollout
found an original `0.75` CPU limit while its source default was `0.35`. The full
fingerprint remains strict; no CPU, DNS or other HostConfig drift is normalized
away. Account-QoS environment activation and its socket owner/mode must also stay
unchanged.

If an assertion fails after recreation, the helper retains the actual inspect
before attempting rollback, then requires the original image, file and running
process digests, zero restarts and exact original runtime fingerprint. Stop on any
failed verification, including failed rollback verification. Retain old images,
journals and full original inspect for recovery; do not proceed to the next node
or recreate Caddy, HAProxy or WireGuard to compensate. `--mode rollback` reuses the
same operation ID and its retained journal.

Artifact transfers have a separate bounded 600-second operational deadline;
application and API request budgets are unchanged. A transfer failure happens
before runtime recreation. If resuming an owned partial upload, first require
its exact byte length and SHA-256 to match the same local prefix, then verify the
complete binary and Dockerfile digests. `--reuse-uploaded` skips copying only;
the remote full-file digest checks and fresh runtime preflight still precede
every apply. Never overwrite a mismatching prefix or remove an unrelated file.

## Validation

The real QUIC peer regression fails before the fix because an uncommitted
response receives a headerless FIN. After the fix, both an unanswered response
and a blocked-header response receive only a stream reset; another stream keeps
transferring. A committed response still delivers its queued body and clean EOF.
The pending-DATA cancellation regression also fails before the fix, and covers
both a closed reader and a fully retired stream without repeated readable events.
The bare-FIN regression fails before the reader notification and passes after
it, including writing a complete response after request EOF.
The complete Rust workspace passed 259 tests, with formatting, clippy and
Markdown checks clean. The production Linux build passed 106 library tests,
two live-credential tests and one endpoint live-reload test, then verified the
static binary. Physical rollout receipts must be retained before declaring
deployment or mobile release acceptance.
