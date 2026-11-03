# Endpoint-only QUIC reliability candidate

This recipe preserves the recorded Jakarta endpoint baseline and adds two
separately reviewed fixes: HTTP/3-before-QUIC shutdown locking, and propagation
of the pending frame's minimum writable capacity. Neither is established as
the cause of historical partial transfers, profile HTTP 504, or low throughput.

The current general node image includes account-QoS and other changes. This
recipe deliberately does not rebuild or replace that image: its output is only
the endpoint binary and provenance files. Existing UDP rejection, live
credentials, pinned h2 capacity backport, locked dependencies, and credentials
ABI 1 remain present. The old h2 regression patch is historical evidence; its
upstream harness is absent from the published crate and is not claimed rerun.

## Verify source assembly offline

Supply a local upstream Git clone and the checksum-pinned h2 crate:

```sh
python3 ops/quic-reliability/test_prepare_source.py \
  --reference /path/to/TrustTunnel \
  --h2-crate /path/to/h2-0.3.27.crate -v
```

Patch files retain their exact reviewed bytes, including unified-diff context
prefixes. Source formatting is checked on the applied Rust tree.

The tests assemble a clean pinned source tree, compare the two reviewed module
hashes and locked dependency input, and reject modified input/source before
mutation. They also verify the actual h2 patched source and reverse application.
A regression control reproduces the old vendor-directory Git application that
could silently skip the dependency patch. The canonical h2 preparer is corrected
too. These checks do not build or deploy an endpoint.

The recorded live binary hash does not by itself establish that the intended h2
backport was effective in that binary. Retained source/build/ELF evidence must
be checked before claiming a canary differs only in the HTTP/3 changes.

## Build a private Linux artifact

Use the existing authorized build path after the exact-toolchain gates pass.
The recipe supports x86-64 Linux/musl only. Its script explicitly resolves
Cargo, rustc and rustdoc 1.95, records their effective versions, runs the
release library/live-credentials tests, rejects a dynamic ELF interpreter and
checks the unchanged credentials-compatible version string.

```sh
docker build --platform linux/amd64 \
  -f ops/quic-reliability/Dockerfile.endpoint \
  --target artifact --output type=local,dest=/private/output .
```

The output contains the binary, source manifest, compiler versions and hashes.
A successful build is not a deployment or a performance acceptance result.

## Bounded private canary

Before starting, record the exact deployed runner image, actual endpoint inode
hash, original service configuration and owned canary identifiers. Use the
existing endpoint-only overlay with the recorded deployed image as its base.
Do not recreate a live service to obtain a canary. First use an isolated,
explicitly owned listener and probe identity; preserve strict TLS identity and
full byte/digest/exit checks. Keep ordinary client traffic on its existing
service. Establish an independent expiry/cleanup guard before exposing the
listener, and verify removal of only the owned resources after the test.

Reserve the shared measurement window explicitly. Keep the same phone binary,
profile, fixture and quality thresholds for comparisons. Record CPU, completion,
errors and cancellations separately from speed. Any production rollout requires
verified artifact provenance, a successful bounded canary, retained rollback,
and a separate coordinated window; no fleet rollout is performed by this recipe.
