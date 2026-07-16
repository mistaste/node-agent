# Rolling back a Hysteria-enabled node agent

The Hysteria-capable agent deliberately keeps `inbounds.json` at schema version
3. The previous v0.2.3 binary ignores the additive `client_secret_json` field,
but it cannot parse an active Hysteria inbound. Do not replace the binary while
such a record remains in the store.

For every node:

1. Delete or disable every Hysteria inbound in the Guardex admin panel.
2. Wait until the node reports each corresponding deployment as `deleted`.
3. Keep a backup: `cp data/inbounds.json data/inbounds.before-v0.2.3-rollback.json`.
4. Run `docker compose exec node-agent node-agent check-rollback-v0.2.3`.
5. Roll back the binary only after the command prints `safe` on every node.

The check is read-only and fails while any active non-VLESS record remains.
Hysteria TLS bundles may stay under `data/tls`; v0.2.3 does not read them.
