#!/usr/bin/env sh
set -eu

# Certbot deploy hook for the node-agent-owned TrustTunnel endpoint. The hook
# copies only a renewed certificate matching the currently desired hostname,
# validates it and its key, then restarts the agent so the endpoint reloads the
# atomic bundle. It never reads or prints client credentials.

NODE_ROOT="${GUARDEX_NODE_ROOT:-/opt/guardex-node}"
TT_ROOT="${TRUSTTUNNEL_ROOT:-${NODE_ROOT}/data/trusttunnel}"
HOSTS_FILE="${TT_ROOT}/hosts.toml"
LINEAGE="${RENEWED_LINEAGE:-}"
DOMAINS="${RENEWED_DOMAINS:-}"

[ -r "$HOSTS_FILE" ] || exit 0
[ -n "$LINEAGE" ] || exit 0
[ -r "$LINEAGE/fullchain.pem" ] || exit 1
[ -r "$LINEAGE/privkey.pem" ] || exit 1

hostname=$(sed -n 's/^hostname = "\([A-Za-z0-9.-]*\)"$/\1/p' "$HOSTS_FILE" | head -n 1)
[ -n "$hostname" ] || exit 1

matched=false
for domain in $DOMAINS; do
    if [ "$domain" = "$hostname" ]; then
        matched=true
        break
    fi
done
[ "$matched" = true ] || exit 0

openssl x509 -in "$LINEAGE/fullchain.pem" -noout -checkhost "$hostname" >/dev/null
cert_public=$(openssl x509 -in "$LINEAGE/fullchain.pem" -pubkey -noout | openssl pkey -pubin -outform DER | openssl sha256)
key_public=$(openssl pkey -in "$LINEAGE/privkey.pem" -pubout -outform DER | openssl sha256)
[ "$cert_public" = "$key_public" ] || exit 1

temporary=$(mktemp -d "${TT_ROOT}/.cert-renew.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT INT TERM
install -m 0644 "$LINEAGE/fullchain.pem" "$temporary/fullchain.pem"
install -m 0600 "$LINEAGE/privkey.pem" "$temporary/privkey.pem"
mv "$temporary/fullchain.pem" "${TT_ROOT}/certs/fullchain.pem"
mv "$temporary/privkey.pem" "${TT_ROOT}/certs/privkey.pem"

cd "$NODE_ROOT"
docker compose restart node-agent >/dev/null
