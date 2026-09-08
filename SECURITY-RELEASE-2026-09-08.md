# Security release — 2026-09-08

Management listeners outside literal loopback now require TLS. Existing fleet installations must be configured before replacing the agent; an old `.env` with `:8099` and no TLS files will fail closed.

1. Provision a publicly trusted certificate for the node's management DNS name. Place `fullchain.pem` and `privkey.pem` in a root-only directory. If using Let's Encrypt symlinks, mount a directory containing their targets or copy the actual files on renewal.
2. Set `AGENT_TLS_HOST_DIR` to that absolute host directory, `AGENT_TLS_CERT_FILE=/run/guardex-management-tls/fullchain.pem`, and `AGENT_TLS_KEY_FILE=/run/guardex-management-tls/privkey.pem` in `.env`. Compose mounts the directory read-only. Keep the existing `AGENT_SECRET` and firewall allowlist.
3. For a new installation, also supply `AGENT_PUBLIC_HOST` to `install.sh`; preflight checks run before installation changes. Registration uses `https://<AGENT_PUBLIC_HOST>:8099`.
4. Update the controller's node URL to that HTTPS address and validate certificate hostname/chain from the controller. Stage one node first, then roll through the fleet. Restart the agent after certificate renewal; the TLS certificate is loaded at startup. Maintain renewal deployment hooks.
5. Deploy the backend HTTPS enforcement only after every active node is reachable through verified HTTPS. A reverse proxy may terminate TLS with the agent bound to a literal loopback address; never publish a plaintext listener.

Go and vulnerable modules are updated, and release Actions are pinned to reviewed commit IDs. The public repository should receive this change as part of a coordinated release, not an unannounced deployment to the existing fleet.

No token rotation, production session revocation, or Git history rewriting is part of this change. The Docker socket still grants broad host control to a compromised agent; replacing its self-update and runner-control architecture remains separate infrastructure work.
