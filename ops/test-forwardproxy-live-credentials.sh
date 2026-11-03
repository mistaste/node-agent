#!/bin/sh
set -eu
cd "${1:?usage: test-forwardproxy-live-credentials.sh patched-forwardproxy-directory}"
# The upstream TestMain starts unrelated fixed-port servers and writes Caddy's
# autosave. Run the actual package implementation with only our isolated tests.
set --
for source in *.go; do
 case "$source" in *_test.go) ;; *) set -- "$@" "$source" ;; esac
done
if [ "${GO_TEST_RACE:-0}" = 1 ]; then
 set -- -race "$@"
fi
if [ -f hard_quota_test.go ]; then set -- "$@" hard_quota_test.go; fi
GOMAXPROCS=${GOMAXPROCS:-2} go test -mod=mod -v -count=1 -timeout=60s "$@" live_credentials_test.go
