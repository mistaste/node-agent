#!/bin/sh
# Isolated Linux network canary. No host qdisc/sysctl/network mutation.
set -eu
fixture=${1:?usage: run-hard-quota-netem.sh absolute-fixture absolute-endpoint}
endpoint=${2:?absolute endpoint required}
case "$fixture:$endpoint" in /*:/*) ;; *) echo 'absolute binary paths required' >&2; exit 1;; esac
name="guardex-quota-netem-$$"
image="guardex-quota-netem:$$"
context=$(mktemp -d /tmp/guardex-quota-netem.XXXXXX)
cleanup() {
 docker rm -f "$name" >/dev/null 2>&1 || true
 docker image rm "$image" >/dev/null 2>&1 || true
 rm -rf "$context"
}
trap cleanup EXIT HUP INT TERM
cat > "$context/Dockerfile" <<'DOCKER'
FROM postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777
RUN apk add --no-cache iproute2
DOCKER
# Build tooling is disposable; both actual test binaries are read-only mounts.
timeout 90s docker build -t "$image" "$context" >&2
timeout 45s docker run --name "$name" --network none \
 --cap-drop ALL --cap-add NET_ADMIN --security-opt no-new-privileges \
 --cpus 1 --memory 256m --pids-limit 128 --read-only \
 --tmpfs /tmp:rw,nosuid,nodev,size=16m \
 -v "$fixture:/fixture:ro" -v "$endpoint:/endpoint:ro" \
 -e GUARDEX_TT_HARD_TEST_BINARY=/endpoint -e GUARDEX_HARD_QUOTA_NETEM=1 \
 --entrypoint /bin/sh "$image" -ec '
 tc qdisc add dev lo root netem delay 20ms 10ms loss 1% seed 42
 tc -s qdisc show dev lo >&2
 /fixture
 tc -s qdisc show dev lo >&2
 '
