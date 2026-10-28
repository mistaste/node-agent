# Node capacity and account fairness

## Current deployment, 28 October 2026

All eight reachable active nodes use persistent `fq_codel` on public egress.
Multiqueue NICs retain `mq`, with `fq_codel` on each transmit queue. The two
disabled nodes (Amsterdam and Istanbul) are unreachable by SSH and unchanged.
This controls local queue delay and separates flows. It does not implement
account-level speed limits, a CPU budget, or repair packet loss elsewhere.

## Recommended rate policy

Use a shared, configurable node budget for the sum of logical upload and
download traffic, then divide that budget with a work-conserving account
scheduler. Count each forwarded byte once, not once on both NIC RX and TX.

An account with no queued data consumes no share. An account with low demand
gets what it needs; other accounts borrow the surplus. Multiple devices,
transport connections and streams of the same account share one account
bucket on that node. A speed test cannot gain extra shares by opening streams.

For example, with a 450 Mbps node budget:

| Demand | Allocation |
| --- | --- |
| One downloading account, nine idle accounts | Up to 450 Mbps to the download |
| Two accounts both demanding over 225 Mbps | About 225 Mbps each |
| One needs 10 Mbps, one needs 500 Mbps | 10 Mbps and about 440 Mbps |

Use equal account weights initially. Keep rate policy separate from monthly
traffic quotas and the connected-device count shown by native presence.

## Budget calibration and adaptation

The short tests indicate provisional pilot budgets of 450 Mbps for Helsinki,
600 Mbps for Wroclaw and 800 Mbps for Frankfurt. These are starting hypotheses,
not validated sustained capacity or currently enforced limits. Calibrate each
node with both traffic directions and supported transports before enabling.

Target approximately 65–75% sustained CPU, retaining steal time as unavailable
capacity. Sample over the whole interval. Reduce the budget by 10% after two
successive five-second windows above 80% CPU. Increase by at most 5% after
30 seconds below 60%, up to the calibrated ceiling. Log adjustments and expose
the current budget and reason in the admin panel. Do not drive this controller
from a single admin TCP-connect latency sample: SYN retransmission and loss on
the backend-to-node path have independently produced one-second outliers.

The first pilot should use explicit bounds and a quick disable switch. Reject
additional automatic placements on a persistently saturated node; preserve
existing connections while reducing bulk demand rather than disconnecting them.

## Required enforcement boundary

Enforce after authentication inside each transport engine, using an internal
account ID supplied by the existing profile registry. Do not query the database
per packet. Reload the profile-to-account map when provisioning/revocation
changes. A profile UUID or device is not an account: combine all its profiles.

Do not use client IP as the account identity. The blind relay is shared by
multiple accounts, and an exit node sees the backbone peer rather than the
original user. CAKE/host isolation or ordinary flow queues cannot recover an
authenticated account hidden inside an encrypted tunnel.

The running TrustTunnel 1.1.0 build exposes per-user traffic metrics and
connection limits, but has no existing bandwidth limiter to enable. NaiveProxy
must participate in the same node/account budget; limiting only
one engine would allow another transport to consume the remaining CPU.

Implement bounded per-account queues with backpressure and small bursts.
Use a common scheduler/token-bucket service across transports, with graceful
fallback if policy delivery fails. Verify TLS and UDP behavior under throttling.

## Acceptance checks for the limiter

- One account using 1 versus 32 connections gets the same total share.
- Two accounts behind the same relay remain separately scheduled.
- Two devices of one account share one budget.
- Idle VPN sessions do not reduce download speed.
- A low-demand account keeps responsive small requests during a bulk download.
- Upload plus download together respect the CPU-safe aggregate budget.
- Protocol switching and reconnects do not create additional shares.
- Budget changes avoid oscillation and preserve active sessions.
- The admin panel shows configured/current budgets and measured per-account rates.

This scheduler is a proposed implementation, not a deployed per-user limit.
