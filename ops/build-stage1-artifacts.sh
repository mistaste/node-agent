#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
OUT_DIR="${GUARDEX_STAGE1_ARTIFACT_DIR:-/tmp/guardex-stage1-artifacts}"
GOOS_TARGET="${GOOS_TARGET:-linux}"
GOARCH_TARGET="${GOARCH_TARGET:-amd64}"

install -d -m 0755 "$OUT_DIR"

build_one() {
  name="$1"
  package="$2"
  output="${OUT_DIR}/${name}-${GOOS_TARGET}-${GOARCH_TARGET}"
  (
    cd "$ROOT"
    GOOS="$GOOS_TARGET" GOARCH="$GOARCH_TARGET" CGO_ENABLED=0 \
      go build -trimpath -ldflags "-s -w" -o "$output" "$package"
  )
  shasum -a 256 "$output"
}

build_one guardex-node-agent .
build_one guardex-topology-agent ./cmd/topology-agent
build_one guardex-trusttunnel-runner ./cmd/trusttunnel-runner
