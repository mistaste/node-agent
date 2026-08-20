#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
OUT_DIR="${GUARDEX_STAGE1_ARTIFACT_DIR:-/tmp/guardex-stage1-artifacts}"
GOOS_TARGET="${GOOS_TARGET:-linux}"
GOARCH_TARGET="${GOARCH_TARGET:-amd64}"
MANIFEST="${OUT_DIR}/stage1-artifacts-manifest.txt"

install -d -m 0755 "$OUT_DIR"

GIT_COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_BRANCH="$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
BUILD_TIME_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

{
  echo "guardex_stage1_artifacts"
  echo "build_time_utc=${BUILD_TIME_UTC}"
  echo "git_branch=${GIT_BRANCH}"
  echo "git_commit=${GIT_COMMIT}"
  echo "target=${GOOS_TARGET}/${GOARCH_TARGET}"
  echo
  echo "sha256:"
} >"$MANIFEST"

build_one() {
  name="$1"
  package="$2"
  output="${OUT_DIR}/${name}-${GOOS_TARGET}-${GOARCH_TARGET}"
  (
    cd "$ROOT"
    GOOS="$GOOS_TARGET" GOARCH="$GOARCH_TARGET" CGO_ENABLED=0 \
      go build -trimpath -ldflags "-s -w" -o "$output" "$package"
  )
  checksum="$(shasum -a 256 "$output")"
  echo "$checksum"
  echo "$checksum" >>"$MANIFEST"
}

build_one guardex-node-agent .
build_one guardex-topology-agent ./cmd/topology-agent
build_one guardex-trusttunnel-runner ./cmd/trusttunnel-runner
build_one guardex-transport-bundle-runner ./cmd/transport-bundle-runner
build_one guardex-transport-bundle-render ./cmd/transport-bundle-render

echo
echo "manifest: ${MANIFEST}"
