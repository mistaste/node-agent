#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
ARTIFACT_DIR="${1:-${GUARDEX_STAGE1_ARTIFACT_DIR:-/tmp/guardex-stage1-artifacts}}"
MANIFEST="${ARTIFACT_DIR}/stage1-artifacts-manifest.txt"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

[ -f "$MANIFEST" ] || fail "missing manifest: $MANIFEST"

manifest_commit="$(sed -n 's/^git_commit=//p' "$MANIFEST" | head -n 1)"
[ -n "$manifest_commit" ] || fail "manifest has no git_commit"

current_commit="$(git -C "$ROOT" rev-parse HEAD)"
[ "$manifest_commit" = "$current_commit" ] || fail "manifest commit $manifest_commit does not match current commit $current_commit"

required="
guardex-node-agent-linux-amd64
guardex-topology-agent-linux-amd64
guardex-trusttunnel-runner-linux-amd64
guardex-transport-bundle-runner-linux-amd64
guardex-transport-bundle-render-linux-amd64
"

for name in $required; do
  [ -f "${ARTIFACT_DIR}/${name}" ] || fail "missing artifact: ${ARTIFACT_DIR}/${name}"
  if ! grep -q "  .*/${name}\$" "$MANIFEST"; then
    fail "manifest does not include sha256 for $name"
  fi
done

tmp="$(mktemp)"
sed -n '/^sha256:/,$p' "$MANIFEST" | sed '1d' > "$tmp"
if ! shasum -a 256 -c "$tmp"; then
  rm -f "$tmp"
  fail "artifact checksum mismatch"
fi
rm -f "$tmp"

echo "OK: Stage 1 artifacts match manifest and current commit"
