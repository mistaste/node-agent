# Node host hardening

`install.sh` installs these files before starting the node containers:

- `firewall/guardex-agent-firewall.sh` and its systemd unit restrict TCP 8099
  to the controller's IPv4 address and deny the port over IPv6;
- `fail2ban/guardex-sshd.local` enables rate limiting for SSH authentication;
- `ssh/00-guardex-hardening.conf` disables password-based SSH authentication.

Set `CONTROLLER_ORIGIN_IP` when installing against a controller other than
`80.241.216.139`. The generated `/etc/guardex/node-firewall.conf` is the durable
source of the controller address and agent port. After changing it, apply the
new rules with:

```sh
systemctl reload guardex-agent-firewall
```

SSH key-only mode is installed only when `/root/.ssh/authorized_keys` is
non-empty and the host's main `sshd_config` includes its drop-in directory. The
installer validates the candidate configuration and its effective values before
reloading SSH.

## Transport Stage 1 activation

Stage 1 separates the transport stack into three duties:

- `node-agent` reconciles desired state and keeps the existing Docker/self-update
  socket, but it must not receive `NET_ADMIN`.
- `topology-agent` owns only WireGuard `gxwg0`, routing policy and nftables. It
  needs `NET_ADMIN`, must not mount `/var/run/docker.sock`, and never receives
  user keys or VPN profile material.
- `trusttunnel-runner` owns only the pinned TrustTunnel endpoint process. It
  reads the node-local `vpn.toml`, `hosts.toml` and `credentials.toml` bundle
  written by `node-agent`; the bundle must remain mode `0600`.

The canary topology is intentionally split so the real VPN exit node is not the
public address a restricted network connects to:

```text
tester app
  -> blind relay on 443
  -> TrustTunnel ingress on 443
  -> private WireGuard backbone gxwg0
  -> exit node public egress
  -> internet
```

Roles:

- `relay` is a fixed L4 forwarder only. It DNAT/SNATs TCP/UDP `443` to one
  configured ingress address and rejects that destination when the route is not
  explicitly enabled. It never receives TrustTunnel certificates, VPN profile
  credentials, WireGuard keys or arbitrary upstream targets, so it cannot become
  an open proxy.
- `ingress` is the IP-hiding layer for the exit node. TrustTunnel terminates
  here, but packets from the endpoint process are policy-routed into `gxwg0`.
  If the WireGuard backbone is missing, nftables rejects the endpoint UID's
  traffic instead of leaking directly from the ingress host.
- `exit` is the only role allowed to NAT backbone traffic to the public
  internet. It accepts traffic from `gxwg0` to its configured egress interface
  and rejects unmatched backbone forwarding.

Before enabling topology roles on a node, run:

```sh
GUARDEX_NODE_ROOT=/opt/guardex-node ./ops/transport-stage1-preflight.sh
```

The activation services live in `docker-compose.stage1.yml` and are not applied
by the default installer. Use it only during the Stage 1 canary:

```sh
docker compose -f docker-compose.yml -f docker-compose.stage1.yml up -d --build
```

Do not enable the legacy `guardex-trusttunnel.service` for Stage 1. It is kept
only for older manual endpoint installs and runs with a broader capability set
than the containerized runner design.

Activation order:

1. Deploy `node-agent` with the new binaries while keeping topology desired state
   disabled.
2. Start `topology-agent` as a separate service/container with `NET_ADMIN` and no
   Docker socket.
3. Start `trusttunnel-runner` as a separate service/container after choosing the
   final file-owner model for the 0600 TrustTunnel bundle.
4. Assign the candidate `ingress` and `exit` roles in the backend while keeping
   both disabled. Wait for each node to report its WireGuard public key to the
   controller.
5. Create the backbone link disabled first, then enable the ingress/exit roles,
   then enable the backbone. Verify `gxwg0`, nftables and fail-closed rules on
   both nodes before exposing any relay address.
6. Assign the `relay` role disabled, create one disabled relay route to the
   ingress public IPv4 on port `443`, then enable the relay role and route only
   for the canary window.
7. Test TCP and UDP 443 through the relay, then check that the
   mobile signed catalog contains relay addresses only for tester accounts.

Build the three Stage 1 node binaries with:

```sh
GUARDEX_STAGE1_ARTIFACT_DIR=/tmp/guardex-stage1-artifacts ./ops/build-stage1-artifacts.sh
```

The backend exposes the operator-only Stage 1 intent API under the admin
session:

```text
GET  /v1/admin/transport/topology/summary
POST /v1/admin/transport/topology/roles
POST /v1/admin/transport/topology/backbone-links
POST /v1/admin/transport/topology/relay-routes
```

Use `/summary` after every change. A route is canary-ready only when:

- both ingress and exit roles show `ready: true`;
- the backbone link shows `ready: true`;
- the relay role shows `ready: true`;
- the relay route targets the ingress public IPv4 on TCP/UDP `443`;
- tester profiles receive relay addresses in the signed mobile catalogue.

Rollback:

```sh
docker compose -f docker-compose.yml -f docker-compose.stage1.yml stop topology-agent trusttunnel-runner
docker compose exec node-agent node-agent check-rollback-v0.2.3
docker compose restart node-agent
```

Then clear the node's topology desired state in the backend with a higher
revision tombstone. The local topology agent removes `gxwg0`, policy rule
priority `100` and the `guardex_transport` nftables table on the next pull.
