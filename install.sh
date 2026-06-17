#!/usr/bin/env bash
set -euxo pipefail

# Guardex Node Agent — one-command Docker setup
# Usage: curl -fsSL https://raw.githubusercontent.com/mistaste/node-agent/master/install.sh | bash

XRAY_PORT="${XRAY_PORT:-443}"
AGENT_PORT="${AGENT_PORT:-8099}"
XRAY_GRPC_PORT="${XRAY_GRPC_PORT:-8080}"
INBOUND_TAG="${INBOUND_TAG:-vless-in}"

NODE_ID="${NODE_ID:-}"
CONTROLLER_URL="${CONTROLLER_URL:-}"
INTERNAL_SERVICE_TOKEN="${INTERNAL_SERVICE_TOKEN:-}"
AGENT_SECRET="${AGENT_SECRET:-$(openssl rand -hex 32)}"

INSTALL_DIR="${INSTALL_DIR:-/opt/guardex-node}"

log()  { echo -e "\033[1;32m[guardex]\033[0m $*"; }
warn() { echo -e "\033[1;33m[guardex]\033[0m $*"; }
die()  { echo -e "\033[1;31m[guardex]\033[0m $*" >&2; exit 1; }

require_root() { [ "$(id -u)" -eq 0 ] || die "Run as root: sudo bash install.sh"; }

# ── install Docker ─────────────────────────────────────────────────────────────
install_docker() {
    if command -v docker >/dev/null 2>&1; then
        log "Docker already installed: $(docker --version)"
        return
    fi
    log "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
    log "Docker installed ✓"
}

# ── generate Reality keys using a temporary xray binary ───────────────────────
generate_reality_keys() {
    log "Generating Reality keypair..."
    local xray_bin="/tmp/xray-keygen"
    local arch; arch=$(uname -m)
    case "$arch" in
        x86_64)  arch="64" ;;
        aarch64) arch="arm64-v8a" ;;
        *) die "Unsupported architecture: $arch" ;;
    esac

    if ! command -v xray >/dev/null 2>&1; then
        log "Downloading xray for key generation..."
        local latest; latest=$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
        curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/${latest}/Xray-linux-${arch}.zip" -o /tmp/xray-keygen.zip
        unzip -o /tmp/xray-keygen.zip xray -d /tmp/
        mv /tmp/xray "$xray_bin"
        chmod +x "$xray_bin"
        rm -f /tmp/xray-keygen.zip
    else
        xray_bin="xray"
    fi

    local keys; keys=$("$xray_bin" x25519)
    REALITY_PRIVATE_KEY=$(echo "$keys" | grep "Private key:" | awk '{print $3}')
    REALITY_PUBLIC_KEY=$(echo  "$keys" | grep "Public key:"  | awk '{print $3}')
    REALITY_SHORT_ID=$(openssl rand -hex 8)

    [ "$xray_bin" = "/tmp/xray-keygen" ] && rm -f "$xray_bin"

    [ -z "$REALITY_PRIVATE_KEY" ] && die "Failed to parse private key from: $keys"
    [ -z "$REALITY_PUBLIC_KEY"  ] && die "Failed to parse public key from: $keys"

    log "Public key:  $REALITY_PUBLIC_KEY"
    log "Short ID:    $REALITY_SHORT_ID"
}

# ── write Xray config ─────────────────────────────────────────────────────────
write_xray_config() {
    log "Writing Xray config to ${INSTALL_DIR}/xray-config.json..."
    mkdir -p "$INSTALL_DIR"
    cat > "$INSTALL_DIR/xray-config.json" <<EOF
{
  "log": { "loglevel": "warning" },
  "api": {
    "tag": "api",
    "services": ["HandlerService", "StatsService"]
  },
  "inbounds": [
    {
      "tag": "api",
      "listen": "127.0.0.1",
      "port": ${XRAY_GRPC_PORT},
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" }
    },
    {
      "tag": "${INBOUND_TAG}",
      "port": ${XRAY_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.google.com:443",
          "serverNames": ["www.google.com"],
          "privateKey": "${REALITY_PRIVATE_KEY}",
          "shortIds": ["${REALITY_SHORT_ID}"]
        }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" }
  ],
  "routing": {
    "rules": [
      { "inboundTag": ["api"], "outboundTag": "direct", "type": "field" }
    ]
  },
  "stats": {},
  "policy": {
    "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } },
    "system": { "statsInboundUplink": true, "statsInboundDownlink": true }
  }
}
EOF
}

# ── write .env for node-agent ─────────────────────────────────────────────────
write_env() {
    log "Writing ${INSTALL_DIR}/.env..."
    cat > "$INSTALL_DIR/.env" <<EOF
XRAY_GRPC_ADDR=127.0.0.1:${XRAY_GRPC_PORT}
AGENT_LISTEN_ADDR=:${AGENT_PORT}
AGENT_SECRET=${AGENT_SECRET}
XRAY_INBOUND_TAG=${INBOUND_TAG}
METRICS_INTERVAL=15s
NODE_ID=${NODE_ID}
CONTROLLER_URL=${CONTROLLER_URL}
INTERNAL_SERVICE_TOKEN=${INTERNAL_SERVICE_TOKEN}
EOF
    chmod 600 "$INSTALL_DIR/.env"
}

# ── clone repo ────────────────────────────────────────────────────────────────
clone_repo() {
    log "Cloning node-agent repo to ${INSTALL_DIR}..."
    if [ -d "$INSTALL_DIR/.git" ]; then
        git -C "$INSTALL_DIR" pull --ff-only
    else
        rm -rf "$INSTALL_DIR"
        git clone https://github.com/mistaste/node-agent.git "$INSTALL_DIR"
    fi
}

# ── start containers ──────────────────────────────────────────────────────────
start_containers() {
    log "Starting containers with Docker Compose..."
    cd "$INSTALL_DIR"
    docker compose pull xray 2>/dev/null || true
    docker compose up -d --build
    sleep 2
    docker compose ps
}

# ── print summary ─────────────────────────────────────────────────────────────
print_summary() {
    local ip; ip=$(curl -fsSL ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║              Guardex Node Setup Complete                 ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    printf "║  Server IP:       %-38s ║\n" "$ip"
    printf "║  Node Agent URL:  %-38s ║\n" "http://$ip:${AGENT_PORT}"
    printf "║  Agent Secret:    %-38s ║\n" "$AGENT_SECRET"
    printf "║  Reality PBK:     %-38s ║\n" "$REALITY_PUBLIC_KEY"
    printf "║  Reality SID:     %-38s ║\n" "$REALITY_SHORT_ID"
    printf "║  Inbound Port:    %-38s ║\n" "$XRAY_PORT"
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║  Add in Admin Panel → Servers → Edit:                    ║"
    echo "║    node_url, node_secret, reality_pbk, reality_short_id  ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    echo "# Save these — the private key never leaves this server:"
    echo "REALITY_PRIVATE_KEY=${REALITY_PRIVATE_KEY}"
    echo "REALITY_PUBLIC_KEY=${REALITY_PUBLIC_KEY}"
    echo "REALITY_SHORT_ID=${REALITY_SHORT_ID}"
    echo "AGENT_SECRET=${AGENT_SECRET}"
    echo ""
    echo "# Manage: cd ${INSTALL_DIR} && docker compose logs -f"
}

# ── main ──────────────────────────────────────────────────────────────────────
main() {
    require_root

    apt-get update -qq
    apt-get install -y -qq curl openssl git

    install_docker
    generate_reality_keys
    clone_repo
    write_xray_config
    write_env
    start_containers
    print_summary
}

main "$@"
