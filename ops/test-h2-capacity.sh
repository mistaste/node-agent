#!/bin/sh
set -eu
patches=$(CDPATH= cd -- "$(dirname -- "$0")/patches" && pwd)
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT HUP INT TERM
git clone --quiet --depth 1 --branch v0.3.27 https://github.com/hyperium/h2.git "$root/h2"
cd "$root/h2"
test "$(git rev-parse HEAD)" = f6237accb3e37668a8d7fb2331f22eb7b808c1e8
git apply "$patches/h2-0.3.27-reclaim-capacity-test.patch"
if cargo test -p h2-tests --test flow_control reclaim_reserved_capacity --release > "$root/negative.log" 2>&1; then
  echo 'Expected the unpatched release regression to fail' >&2
  exit 1
fi
grep -q 'assertion failed: self.window_size.0 >= sz as i32' "$root/negative.log"
git apply "$patches/h2-0.3.27-reclaim-capacity.patch"
cargo test -p h2-tests --test flow_control reclaim_reserved_capacity --release
cargo test -p h2-tests
