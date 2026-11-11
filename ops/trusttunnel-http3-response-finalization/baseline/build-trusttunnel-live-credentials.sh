#!/bin/sh
# Pinned source build; run in the reviewed core-libs cross compiler image.
set -eu
export RUSTUP_TOOLCHAIN=1.95
export TRUSTTUNNEL_VERSION=1.1.0-guardex-account-qos.1
case "${1:?target architecture required}" in
  amd64) arch=x86_64 ;;
  arm64) arch=aarch64 ;;
  *) echo 'Unsupported endpoint architecture' >&2; exit 1 ;;
esac
target="$arch-unknown-linux-musl"
export CC="$arch-linux-musl-gcc"
export CXX="$arch-linux-musl-g++"
export BINDGEN_EXTRA_CLANG_ARGS="--sysroot=/opt/cross/$arch-linux-musl"
command -v "$CC"
command -v "$CXX"
rustup target add "$target"
cd "${GUARDEX_ENDPOINT_SOURCE:-/trusttunnel-source}"
if [ "$arch" = x86_64 ]; then
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc
  cargo test --release --locked --target "$target" -j 2 -p trusttunnel --lib
  cargo test --release --locked --target "$target" -j 2 -p trusttunnel --test live_credentials
  cargo test --release --locked --target "$target" -j 2 -p trusttunnel_endpoint live_reload_tests
else
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc
fi
cargo build --release --locked --target "$target" --bin trusttunnel_endpoint -j 2
binary="target/$target/release/trusttunnel_endpoint"
if readelf -l "$binary" | grep -q INTERP; then
  echo 'Dynamic endpoint interpreter is forbidden' >&2
  exit 1
fi
if [ "$arch" = x86_64 ]; then
  test "$("$binary" --version)" = "$TRUSTTUNNEL_VERSION"
fi
cp "$binary" "${GUARDEX_ENDPOINT_OUTPUT:-/trusttunnel_endpoint}"
sha256sum "${GUARDEX_ENDPOINT_OUTPUT:-/trusttunnel_endpoint}"
