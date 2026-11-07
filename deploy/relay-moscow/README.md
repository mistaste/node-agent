# Moscow relay TCP segmentation

The renewed Moscow VPS returned with TSO/GSO enabled on its `ens3` interface.
Concurrent native TrustTunnel tests reproduced partial downloads, health-check
recovery and stalled uploads. Packet captures showed substantial packet
reordering on the public client side. The same parallel test completed 60/60
requests after disabling TSO/GSO, versus 50/60 before the change, with unchanged
TLS, application deadlines, client binaries and relay routing. The test included
all six destinations and three Finland sessions with 30-second idle reuse.

An independent Russian-source control subsequently completed 38/40 requests:
one Finland upload and one Indonesia connection still timed out. Retaining this
mitigation does not establish that all remaining timeouts have been resolved.
Preserve failed receipts alongside successful runs; do not relax deadlines or
TLS verification to qualify the deployment.

This unit retains the tested software segmentation setting before Docker starts
after reboot. It does not restart relay containers or alter credentials,
encryption, routing, TCP congestion control or MTU. The test establishes a
successful mitigation; it does not identify a particular provider device fault.

Install only on the verified Moscow host `138.16.163.18`, after confirming its
interface remains `ens3` and that the original TSO/GSO settings are both on.
Save the original feature output and arm an independent timed rollback before
the live trial. Validate with `systemd-analyze verify`, then enable/start the unit
only after native transfer acceptance. Verify both feature flags are off before
retiring the timed rollback.

Rollback: stop and disable this exact unit. Its ExecStop restores the original
TSO/GSO settings. Keep the saved feature snapshot and acceptance receipts under
`/var/lib/guardex-remediation/moscow-segmentation-20261107`.
