#!/bin/sh
set -eu
export RUSTUP_TOOLCHAIN=1.95
rustup toolchain install 1.95 --profile minimal
rustup target add --toolchain 1.95 x86_64-unknown-linux-musl
export RUSTC="$(rustup which --toolchain 1.95 rustc)"
export RUSTDOC="$(rustup which --toolchain 1.95 rustdoc)"
cargo_bin="$(rustup which --toolchain 1.95 cargo)"
export PATH="$(dirname "$RUSTC"):$PATH"
"$RUSTC" --version | tee /out/rustc-version.txt
"$cargo_bin" --version | tee /out/cargo-version.txt
"$RUSTDOC" --version | tee /out/rustdoc-version.txt
grep -q '^rustc 1.95.' /out/rustc-version.txt
grep -q '^cargo 1.95.' /out/cargo-version.txt
grep -q '^rustdoc 1.95.' /out/rustdoc-version.txt
export TRUSTTUNNEL_VERSION=1.1.0-guardex-live-credentials.1
export CC=x86_64-linux-musl-gcc
export CXX=x86_64-linux-musl-g++
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc
export BINDGEN_EXTRA_CLANG_ARGS=--sysroot=/opt/cross/x86_64-linux-musl
cd /trusttunnel-source
"$cargo_bin" test --release --locked --target x86_64-unknown-linux-musl -j 2 -p trusttunnel --lib
"$cargo_bin" test --release --locked --target x86_64-unknown-linux-musl -j 2 -p trusttunnel --test live_credentials
"$cargo_bin" test --release --locked --target x86_64-unknown-linux-musl -j 2 -p trusttunnel_endpoint live_reload_tests
"$cargo_bin" build --release --locked --target x86_64-unknown-linux-musl --bin trusttunnel_endpoint -j 2
binary=target/x86_64-unknown-linux-musl/release/trusttunnel_endpoint
if readelf -l "$binary" | grep -q INTERP; then
    echo 'Dynamic endpoint interpreter is forbidden' >&2
    exit 1
fi
test "$("$binary" --version)" = "$TRUSTTUNNEL_VERSION"
cp "$binary" /out/trusttunnel_endpoint
cp /recipe/manifest.json /out/source-manifest.json
(cd /out && sha256sum trusttunnel_endpoint source-manifest.json prepared-source.json rustc-version.txt cargo-version.txt rustdoc-version.txt > SHA256SUMS)
