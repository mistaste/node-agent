#!/bin/sh
set -eu
cd "${GUARDEX_ENDPOINT_SOURCE:-/trusttunnel-source}"
patches_dir="${GUARDEX_ENDPOINT_PATCHES:-/patches}"
test ! -e vendor/h2
archive="$(mktemp)"
trap 'rm -f "$archive"' EXIT
if [ -n "${GUARDEX_H2_ARCHIVE:-}" ]; then
    cp "$GUARDEX_H2_ARCHIVE" "$archive"
else
    curl --fail --silent --show-error --location https://static.crates.io/crates/h2/h2-0.3.27.crate -o "$archive"
fi
python3 -c 'import hashlib,pathlib,sys; sys.exit(0 if hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()==sys.argv[2] else "h2 archive checksum mismatch")' "$archive" 0beca50380b1fc32983fc1cb4587bfa4bb9e78fc259aad4a0032d2080309222d
mkdir -p vendor/h2
tar -xzf "$archive" --strip-components=1 -C vendor/h2
# Applying from a Git subdirectory can silently skip paths outside that prefix.
git apply --check --directory=vendor/h2 "$patches_dir/h2-capacity.patch"
git apply --directory=vendor/h2 "$patches_dir/h2-capacity.patch"
python3 -c 'import hashlib,pathlib,sys; sys.exit(0 if hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()==sys.argv[2] else "patched h2 source checksum mismatch")' vendor/h2/src/proto/streams/prioritize.rs d665243430b46c07854116e7facbc60779cd40dbdb7b79fd55953be93c146012
git apply --reverse --check --directory=vendor/h2 "$patches_dir/h2-capacity.patch"
printf '\n[patch.crates-io]\nh2 = { path = "vendor/h2" }\n' >> Cargo.toml
cp "$patches_dir/endpoint.lock" Cargo.lock
