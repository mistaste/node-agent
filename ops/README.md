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
4. Wait for each node to report its WireGuard public key to the controller.
5. Assign one ingress and one exit in the backend, keep relay routes disabled,
   and verify `gxwg0`, nftables and fail-closed rules on both nodes.
6. Enable one tester-only relay route, test TCP and UDP 443, then check that the
   mobile signed catalog contains relay addresses only for tester accounts.

Rollback:

```sh
docker compose -f docker-compose.yml -f docker-compose.stage1.yml stop topology-agent trusttunnel-runner
docker compose exec node-agent node-agent check-rollback-v0.2.3
docker compose restart node-agent
```

Then clear the node's topology desired state in the backend with a higher
revision tombstone. The local topology agent removes `gxwg0`, policy rule
priority `100` and the `guardex_transport` nftables table on the next pull.
