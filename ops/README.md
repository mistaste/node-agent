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
