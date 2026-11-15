# Repair credential reload runner compatibility

An endpoint may support live credential updates while its older runner does not
recognize the endpoint's version. In that case the runner omits
`credential_reload_version: 1` from `runner-state.json`; the agent safely falls
back to a full endpoint restart for every membership change. This disconnects
unrelated users. A healthy listener and a correct endpoint version alone do not
prove live updates work. Check the runner acknowledgement too.

The runner in master recognizes the reviewed `account-qos.1`, `live-credentials.1`
and `hard-quota.1` versions. Do not broaden this list to arbitrary versions.

Build the static Linux runner from an identified reviewed commit, run
`go test ./cmd/trusttunnel-runner ./internal/trusttunnel`, then run the actual
`ops/test_live_credentials_endpoint.py` gate using the exact deployed endpoint
binary and candidate runner on isolated loopback fixtures. The gate verifies
that adding/removing Bob preserves Alice's original 8 MiB stream and endpoint
PID, and rejects malformed credentials and revoked access.

`rollout.py` stages a runner-only overlay of the exact current image, preserves
the endpoint and compares complete Config, HostConfig and mount fingerprints.
It changes only `trusttunnel-runner`; original Compose files stay untouched.
Private inspect backups remain in the root-only deployment directory outside
the Docker build context. Supply the full current image ID and candidate runner
SHA-256 explicitly. Without `--apply` it only checks the prepared inputs.

Use a new root-only directory for each attempt containing `trusttunnel-runner`:

```sh
python3 rollout.py --directory /opt/guardex-node/ops/credential-runner-YYYYMMDD \
  --runner-sha256 FULL_CANDIDATE_SHA256 --expected-image sha256:FULL_CURRENT_IMAGE_ID
```

After checking preflight, add `--apply` for one node. It retains the old image,
waits for credential acknowledgement, checks the running endpoint bytes,
unchanged resources/security/environment/mounts, then waits and checks again.
Any failure after recreation triggers restoration of the previous image and
verification. A build failure occurs before recreation. The owned Compose
override remains active and is included in subsequent rollout inputs.

Verify real tunnel payload and controller freshness on the first node before
applying to another. This repairs an incomplete rollout; it does not change
transport versions, bypass access checks or guarantee reachability through a
particular mobile operator.

Run the preservation regression tests with:

```sh
python3 -m unittest discover -s ops/credential-runner -p 'test_*.py'
```
