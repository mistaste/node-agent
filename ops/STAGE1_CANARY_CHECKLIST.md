# Guardex Transport Resilience — Stage 1 canary checklist

This checklist is the operator evidence file for the first physical iOS/Android
tests of:

```text
tester app -> blind relay:443 -> TrustTunnel ingress:443 -> gxwg0 WireGuard backbone -> exit egress
```

## Code gates

- Backend migrations for transport roles, backbone links, relay routes and
  observed node state are applied.
- Backend `/v1/admin/transport/topology/summary` is available in the admin
  panel under `/admin/transport`.
- Backend publishes `relay_addresses` to signed tester catalogues only when all
  readiness gates are true:
  - relay role enabled and observed at the latest relay route revision;
  - ingress role enabled, observed and has a WireGuard public key;
  - exit role enabled, observed and has a WireGuard public key;
  - latest ingress backbone is enabled and observed on both endpoints;
  - relay route is enabled, fixed to ingress TCP/UDP `443`.
- Mobile TrustTunnel connects through assigned relay addresses only. If a
  signed relay is present, direct ingress fallback is not used.
- Tester diagnostics preflight checks the relay address first when one is
  assigned.
- Node-agent Stage 1 containers keep capabilities split:
  - `node-agent`: no `NET_ADMIN`;
  - `topology-agent`: `NET_ADMIN`, no Docker socket;
  - `trusttunnel-runner`: `NET_BIND_SERVICE`, no `NET_ADMIN`.

## Production prerequisites

Do not start canary until these are done intentionally:

1. Deploy backend with the Stage 1 topology API and catalogue signer.
2. Install `TRANSPORT_CATALOG_ED25519_PRIVATE_KEY` on production backend.
3. Deploy web/admin with the Transport topology page.
4. Deploy node-agent artifacts containing `node-agent`, `topology-agent` and
   `trusttunnel-runner`.
5. Start Stage 1 compose override on chosen canary nodes only.
6. Choose concrete nodes:
   - `relay`: public IP exposed to tester networks;
   - `ingress`: TrustTunnel endpoint, public TCP/UDP 443 target of relay;
   - `exit`: final VPN egress IP.

## Activation evidence

Before exposing relay addresses to testers:

1. Render activation commands:

   ```sh
   ADMIN_CSRF_TOKEN=... \
   INGRESS_SERVER_ID=... \
   EXIT_SERVER_ID=... \
   RELAY_SERVER_ID=... \
   INGRESS_PUBLIC_IPV4=... \
   ./ops/render-stage1-intent-curl.sh
   ```

2. Create disabled ingress/exit roles and verify both nodes report WireGuard
   public keys.
3. Create disabled backbone link.
4. Enable ingress/exit roles, then enable backbone.
5. Verify `/admin/transport`:
   - ingress role `Ready`;
   - exit role `Ready`;
   - backbone link `Ready`.
6. Create disabled relay role and route.
7. Enable relay role and route.
8. Verify `/admin/transport`:
   - relay role `Ready`;
   - relay route `Ready`;
   - no `*_revision_not_applied` reasons remain.
9. Verify tester account receives signed TrustTunnel methods with
   `relay_addresses`.
10. Verify regular user accounts do not receive tester-only TrustTunnel canary
    routes if the rollout is tester-gated.

## Physical test evidence

For each platform:

- iOS:
  - app opens after reinstall/update;
  - TrustTunnel method appears only for tester;
  - first connect succeeds through relay;
  - app resumes from background and still shows connected state;
  - IP shown in app/site is exit IP, not relay or ingress;
  - disconnect clears VPN icon and app state.
- Android:
  - build installs on phone/tablet form factors;
  - TrustTunnel method appears only for tester;
  - diagnostics quick/full use relay address when assigned;
  - connect/disconnect lifecycle does not race with diagnostics.

## Rollback evidence

If canary fails, render rollback commands:

```sh
ADMIN_CSRF_TOKEN=... \
INGRESS_SERVER_ID=... \
EXIT_SERVER_ID=... \
RELAY_SERVER_ID=... \
INGRESS_PUBLIC_IPV4=... \
./ops/render-stage1-rollback-curl.sh
```

Rollback order must be:

1. disable relay route;
2. disable relay role;
3. disable backbone;
4. disable ingress/exit roles;
5. stop Stage 1 containers if needed;
6. verify `/admin/transport` no longer publishes ready relay routes.
