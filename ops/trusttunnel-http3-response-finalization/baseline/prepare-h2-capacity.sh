#!/bin/sh
set -eu
cd "${GUARDEX_ENDPOINT_SOURCE:-/trusttunnel-source}"
test ! -e vendor/h2
mkdir -p vendor/h2
curl --fail --silent --show-error --location https://static.crates.io/crates/h2/h2-0.3.27.crate -o /tmp/guardex-h2.crate
echo '0beca50380b1fc32983fc1cb4587bfa4bb9e78fc259aad4a0032d2080309222d  /tmp/guardex-h2.crate' | sha256sum -c -
tar -xzf /tmp/guardex-h2.crate --strip-components=1 -C vendor/h2
(cd vendor/h2 && git apply /patches/h2-capacity.patch)
printf '\n[patch.crates-io]\nh2 = { path = "vendor/h2" }\n' >> Cargo.toml
cp /patches/endpoint.lock Cargo.lock
rm /tmp/guardex-h2.crate
