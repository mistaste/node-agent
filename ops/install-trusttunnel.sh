#!/usr/bin/env bash
set -Eeuo pipefail

# Installs the audited, pinned TrustTunnel endpoint without enabling it. The
# Guardex node agent starts it only after a valid catalogue route and TLS files
# are present. Existing Xray listeners are untouched.

VERSION="${TRUSTTUNNEL_VERSION:-1.0.33}"
INSTALL_ROOT="${TRUSTTUNNEL_INSTALL_ROOT:-/opt/trusttunnel}"
CONFIG_ROOT="${TRUSTTUNNEL_ROOT:-/etc/guardex/trusttunnel}"
SERVICE_NAME="guardex-trusttunnel.service"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64)
    ARCH="x86_64"
    EXPECTED_SHA256="48802662bc745aed60207c6ed6465d9fed428b1e53532045689d89bcad19bdd9"
    ;;
  aarch64|arm64)
    ARCH="aarch64"
    EXPECTED_SHA256="8b0d13d11f607c1da18be921096de3f85af67520b305aad425c74dd4f6775697"
    ;;
  *)
    echo "Unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

if [ "$VERSION" != "1.0.33" ]; then
  echo "Unreviewed TrustTunnel version: $VERSION" >&2
  exit 1
fi

ARCHIVE="trusttunnel-v${VERSION}-linux-${ARCH}.tar.gz"
URL="https://github.com/TrustTunnel/TrustTunnel/releases/download/v${VERSION}/${ARCHIVE}"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TEMP_DIR"' EXIT

curl --proto '=https' --tlsv1.2 -fL "$URL" -o "$TEMP_DIR/$ARCHIVE"
printf '%s  %s\n' "$EXPECTED_SHA256" "$TEMP_DIR/$ARCHIVE" | sha256sum -c -
tar -xzf "$TEMP_DIR/$ARCHIVE" -C "$TEMP_DIR"
ENDPOINT="$(find "$TEMP_DIR" -type f -name trusttunnel_endpoint -perm -u+x -print -quit)"
if [ -z "$ENDPOINT" ]; then
  echo "Release archive does not contain trusttunnel_endpoint" >&2
  exit 1
fi

install -d -m 0755 "$INSTALL_ROOT"
install -m 0755 "$ENDPOINT" "$INSTALL_ROOT/trusttunnel_endpoint"
install -d -m 0700 "$CONFIG_ROOT/certs"
install -m 0644 "$SCRIPT_DIR/systemd/guardex-trusttunnel.service" "/etc/systemd/system/$SERVICE_NAME"
systemctl daemon-reload
systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true

"$INSTALL_ROOT/trusttunnel_endpoint" --version
echo "TrustTunnel endpoint v$VERSION installed but not enabled."
echo "Place a valid certificate at $CONFIG_ROOT/certs/fullchain.pem and its key at $CONFIG_ROOT/certs/privkey.pem."
