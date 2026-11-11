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
The baseline runtime version string is retained; identify this correction by
the binary SHA-256 and overlay image digest.
BuildKit caches compiler outputs without changing the pinned source, compiler,
test commands or static-binary checks. An empty cache supports the same build.

For each node, derive an overlay from that node's exact deployed image digest
using `Dockerfile.overlay` and a context containing only the verified binary.
Retain the old image and compose configuration. Recreate only
`trusttunnel-runner`, verify health, credentials, quota enforcement and physical
HTTP/2/HTTP/3 traffic, then proceed to the next node. Other node services and
quota limits are outside this change. Roll back by restoring the prior image
and recreating the same service.

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
Markdown checks clean. Linux production-build and physical rollout receipts
must be retained before declaring deployment or mobile release acceptance.
