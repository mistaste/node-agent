# HTTP/2 reserved capacity fix

The endpoint's h2 0.3.27 dependency can panic when a stream is closed after
exhausting the connection window: it reclaims requested capacity that was
never assigned. Backport upstream [PR 832](https://github.com/hyperium/h2/pull/832)
without changing HTTP versions, routing, TLS or credential reload ABI.

The build verifies the published crate SHA-256, applies the source patch and
uses a Cargo patch so direct h2 and Hyper share the corrected implementation.
Version remains `1.1.0-guardex-live-credentials.1` because the deployed runner
checks this exact credential-reload ABI marker. Identify this binary by its
SHA-256, not by that compatibility marker alone.

Run `sh ops/test-h2-capacity.sh` for the negative control and fixed suite.

Regression: clone h2 v0.3.27 at f6237accb3e37668a8d7fb2331f22eb7b808c1e8,
apply `h2-0.3.27-reclaim-capacity-test.patch`, then run
`cargo test -p h2-tests --test flow_control reclaim_reserved_capacity --release`.
It must fail before applying the source patch and pass afterward. Run the
remaining h2-tests suite after applying both patches.

This reproduced dependency defect is not proof of the historical Dronten
SIGABRT cause: that crash's core was lost. No production crash reproduction
or elimination is claimed solely from this regression.
