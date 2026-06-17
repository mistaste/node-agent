#!/usr/bin/env bash
set -euo pipefail

# Guardex Node Agent — one-command server setup
# Usage: curl -fsSL https://raw.githubusercontent.com/mistaste/node-agent/master/install.sh | bash
# Or with env vars:
#   NODE_ID=<uuid> CONTROLLER_URL=https://api.example.com INTERNAL_SERVICE_TOKEN=xxx bash install.sh

XRAY_VERSION="${XRAY_VERSION:-v25.3.6}"
XRAY_PORT="${XRAY_PORT:-443}"
AGENT_PORT="${AGENT_PORT:-8099}"
XRAY_GRPC_PORT="${XRAY_GRPC_PORT:-8080}"
INBOUND_TAG="${INBOUND_TAG:-vless-in}"

NODE_ID="${NODE_ID:-}"
CONTROLLER_URL="${CONTROLLER_URL:-}"
INTERNAL_SERVICE_TOKEN="${INTERNAL_SERVICE_TOKEN:-}"
AGENT_SECRET="${AGENT_SECRET:-$(openssl rand -hex 32)}"

# ── helpers ───────────────────────────────────────────────────────────────────
log()  { echo -e "\033[1;32m[guardex]\033[0m $*"; }
warn() { echo -e "\033[1;33m[guardex]\033[0m $*"; }
die()  { echo -e "\033[1;31m[guardex]\033[0m $*" >&2; exit 1; }

require_root() { [ "$(id -u)" -eq 0 ] || die "Run as root: sudo bash install.sh"; }
require_cmd()  { command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }

# ── install Xray ──────────────────────────────────────────────────────────────
install_xray() {
    log "Installing Xray-core ${XRAY_VERSION}..."
    local arch; arch=$(uname -m)
    case "$arch" in
        x86_64)  arch="64" ;;
        aarch64) arch="arm64-v8a" ;;
        *) die "Unsupported architecture: $arch" ;;
    esac

    local url="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${arch}.zip"
    curl -fsSL "$url" -o /tmp/xray.zip
    unzip -o /tmp/xray.zip xray -d /usr/local/bin/
    chmod +x /usr/local/bin/xray
    rm /tmp/xray.zip
    log "Xray installed: $(xray version | head -1)"
}

# ── generate Reality keys ─────────────────────────────────────────────────────
generate_reality_keys() {
    log "Generating Reality keypair..."
    local keys; keys=$(xray x25519)
    REALITY_PRIVATE_KEY=$(echo "$keys" | grep "Private key:" | awk '{print $3}')
    REALITY_PUBLIC_KEY=$(echo  "$keys" | grep "Public key:"  | awk '{print $3}')
    REALITY_SHORT_ID=$(openssl rand -hex 8)
    log "Public key:  $REALITY_PUBLIC_KEY"
    log "Short ID:    $REALITY_SHORT_ID"
}

# ── write Xray config ─────────────────────────────────────────────────────────
write_xray_config() {
    log "Writing Xray config..."
    mkdir -p /etc/xray
    cat > /etc/xray/config.json <<EOF
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

# ── create Xray systemd service ───────────────────────────────────────────────
install_xray_service() {
    log "Installing Xray systemd service..."
    cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray VPN Core
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable xray
    systemctl restart xray
    sleep 1
    systemctl is-active --quiet xray && log "Xray running ✓" || warn "Xray may not be running — check: systemctl status xray"
}

# ── install Node Agent ─────────────────────────────────────────────────────────
install_node_agent() {
    log "Installing Guardex Node Agent..."
    local arch; arch=$(uname -m)
    case "$arch" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *) die "Unsupported architecture: $arch" ;;
    esac

    local release_url="https://github.com/mistaste/node-agent/releases/latest/download/node-agent-linux-${arch}"
    if ! curl -fsSL "$release_url" -o /usr/local/bin/node-agent 2>/dev/null; then
        warn "No pre-built binary found. Building from source..."
        require_cmd go
        local tmpdir; tmpdir=$(mktemp -d)
        git clone https://github.com/mistaste/node-agent.git "$tmpdir/node-agent"
        cd "$tmpdir/node-agent"
        GOFLAGS="" go build -ldflags="-checklinkname=0" -o /usr/local/bin/node-agent .
        rm -rf "$tmpdir"
    fi
    chmod +x /usr/local/bin/node-agent
    log "Node Agent installed"
}

# ── create Node Agent env file and service ────────────────────────────────────
install_agent_service() {
    log "Installing Node Agent systemd service..."
    mkdir -p /etc/guardex

    cat > /etc/guardex/node-agent.env <<EOF
XRAY_GRPC_ADDR=127.0.0.1:${XRAY_GRPC_PORT}
AGENT_LISTEN_ADDR=:${AGENT_PORT}
AGENT_SECRET=${AGENT_SECRET}
XRAY_INBOUND_TAG=${INBOUND_TAG}
METRICS_INTERVAL=15s
NODE_ID=${NODE_ID}
CONTROLLER_URL=${CONTROLLER_URL}
INTERNAL_SERVICE_TOKEN=${INTERNAL_SERVICE_TOKEN}
EOF
    chmod 600 /etc/guardex/node-agent.env

    cat > /etc/systemd/system/node-agent.service <<EOF
[Unit]
Description=Guardex Node Agent
After=xray.service
Requires=xray.service

[Service]
Type=simple
EnvironmentFile=/etc/guardex/node-agent.env
ExecStart=/usr/local/bin/node-agent
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable node-agent
    systemctl restart node-agent
    sleep 1
    systemctl is-active --quiet node-agent && log "Node Agent running ✓" || warn "Node Agent may not be running — check: systemctl status node-agent"
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
}

# ── main ──────────────────────────────────────────────────────────────────────
main() {
    require_root
    require_cmd curl
    require_cmd unzip
    require_cmd openssl

    log "Starting Guardex node setup..."

    apt-get update -qq
    apt-get install -y -qq curl unzip openssl

    install_xray
    generate_reality_keys
    write_xray_config
    install_xray_service
    install_node_agent
    install_agent_service
    print_summary
}

main "$@"
