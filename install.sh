#!/usr/bin/env bash
set -Eeo pipefail

# Guardex Node Agent — one-command Docker setup
# Usage: curl -fsSL https://raw.githubusercontent.com/mistaste/node-agent/master/install.sh | bash

XRAY_PORT="${XRAY_PORT:-443}"
AGENT_PORT="${AGENT_PORT:-8099}"
XRAY_GRPC_PORT="${XRAY_GRPC_PORT:-8080}"
INBOUND_TAG="${INBOUND_TAG:-vless-in}"
CONTROLLER_ORIGIN_IP="${CONTROLLER_ORIGIN_IP:-80.241.216.139}"

# Pin xray-core close to the version the Flutter app's proxy_core bundles
# (GFW-knocker fork v1.26.5-mahsa, based on upstream 26.5). Reality handshakes only
# succeed when client and server speak the same protocol generation. Keep this in
# lockstep with proxy_core's xray-core (and docker-compose.yml).
XRAY_VERSION="26.6.1"
XRAY_IMAGE="ghcr.io/xtls/xray-core:${XRAY_VERSION}@sha256:3943bddece5fab72308a4415917f0391917b7b81ddbf50708988b89e6e2bd213"

NODE_ID="${NODE_ID:-}"
CONTROLLER_URL="${CONTROLLER_URL:-https://api.guardex-vpn.com}"
INTERNAL_SERVICE_TOKEN="${INTERNAL_SERVICE_TOKEN:-}"
AGENT_SECRET="${AGENT_SECRET:-$(openssl rand -hex 32)}"
REGISTRATION_STATUS=""  # set by register_node()

# ── prompt for token if not set ───────────────────────────────────────────────
prompt_token() {
    [ -n "$INTERNAL_SERVICE_TOKEN" ] && return

    # curl | bash — stdin не терминал, нельзя читать
    if [ ! -t 0 ]; then
        warn "INTERNAL_SERVICE_TOKEN не задан — авторегистрация пропущена."
        warn "Запусти скрипт снова: bash /tmp/install.sh  (не через curl | bash)"
        return
    fi

    echo ""
    read -rsp "  Введи Internal Service Token: " INTERNAL_SERVICE_TOKEN
    echo ""
    echo ""
}

INSTALL_DIR="${INSTALL_DIR:-/opt/guardex-node}"

log()  { echo -e "\033[1;32m[guardex]\033[0m $*"; }
warn() { echo -e "\033[1;33m[guardex]\033[0m $*"; }
die()  { echo -e "\033[1;31m[guardex]\033[0m $*" >&2; exit 1; }

require_root() { [ "$(id -u)" -eq 0 ] || die "Run as root: sudo bash install.sh"; }
require_systemd() {
    command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] \
        || die "A systemd-based Linux distribution is required"
}

install_prerequisites() {
    log "Installing prerequisites..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            ca-certificates curl fail2ban git iptables openssl
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q ca-certificates curl git iptables openssl
        dnf install -y -q fail2ban || die "Install fail2ban (EPEL may be required), then run the installer again"
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q ca-certificates curl git iptables openssl
        yum install -y -q fail2ban || die "Install fail2ban (EPEL may be required), then run the installer again"
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache ca-certificates curl fail2ban git iptables openssl
    else
        die "Unsupported package manager"
    fi
}

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

# ── generate Reality keys with an immutable, multi-architecture Xray image ────
generate_reality_keys() {
    log "Generating Reality keypair..."
    local keys
    keys=$(docker run --rm --pull=always "$XRAY_IMAGE" x25519)
    REALITY_PRIVATE_KEY=$(echo "$keys" | grep -E "PrivateKey:|Private key:" | awk '{print $NF}')
    REALITY_PUBLIC_KEY=$(echo  "$keys" | grep -E "PublicKey|Public key:"   | awk '{print $NF}')
    REALITY_SHORT_ID=$(openssl rand -hex 8)

    [ -z "$REALITY_PRIVATE_KEY" ] && die "Failed to parse the generated Reality private key"
    [ -z "$REALITY_PUBLIC_KEY"  ] && die "Failed to parse the generated Reality public key"

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
      { "inboundTag": ["api"], "outboundTag": "api", "type": "field" }
    ]
  },
  "stats": {},
  "policy": {
    "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } },
    "system": { "statsInboundUplink": true, "statsInboundDownlink": true }
  }
}
EOF
    chmod 600 "$INSTALL_DIR/xray-config.json"
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
CONTROLLER_ORIGIN_IP=${CONTROLLER_ORIGIN_IP}
USERS_FILE=/data/users.json
INBOUNDS_FILE=/data/inbounds.json
HYSTERIA_TLS_DIR=/etc/guardex/tls
RESYNC_INTERVAL=30s
XRAY_CORE_VERSION=${XRAY_VERSION}
AGENT_VERSION=git
AGENT_REPO_DIR=${INSTALL_DIR}
AGENT_UPDATE_REF=master
EOF
    chmod 600 "$INSTALL_DIR/.env"
}

# ── protect the privileged management API before starting its container ──────
install_management_firewall() {
    command -v systemctl >/dev/null 2>&1 || die "systemd is required for the persistent management firewall"

    log "Restricting node-agent TCP ${AGENT_PORT} to ${CONTROLLER_ORIGIN_IP}..."
    install -D -m 0755 \
        "$INSTALL_DIR/ops/firewall/guardex-agent-firewall.sh" \
        /usr/local/sbin/guardex-agent-firewall
    install -D -m 0644 \
        "$INSTALL_DIR/ops/systemd/guardex-agent-firewall.service" \
        /etc/systemd/system/guardex-agent-firewall.service
    install -d -m 0755 /etc/guardex
    {
        printf 'CONTROLLER_ORIGIN_IP=%s\n' "$CONTROLLER_ORIGIN_IP"
        printf 'AGENT_PORT=%s\n' "$AGENT_PORT"
    } > /etc/guardex/node-firewall.conf
    chmod 0644 /etc/guardex/node-firewall.conf

    systemctl daemon-reload
    systemctl enable --now guardex-agent-firewall.service
    systemctl is-active --quiet guardex-agent-firewall.service \
        || die "Management firewall service did not become active"
}

# ── rate-limit SSH authentication attempts ───────────────────────────────────
install_fail2ban() {
    command -v fail2ban-client >/dev/null 2>&1 || die "fail2ban is required"
    command -v systemctl >/dev/null 2>&1 || die "systemd is required for fail2ban"

    log "Enabling fail2ban for SSH..."
    install -D -m 0644 \
        "$INSTALL_DIR/ops/fail2ban/guardex-sshd.local" \
        /etc/fail2ban/jail.d/guardex-sshd.local
    fail2ban-client -t >/dev/null
    systemctl enable fail2ban.service >/dev/null
    systemctl restart fail2ban.service
    fail2ban-client status sshd >/dev/null \
        || die "fail2ban SSH jail did not become active"
}

restore_ssh_dropin() {
    local backup="$1"
    local had_previous="$2"
    if [ "$had_previous" = "yes" ]; then
        cp -p "$backup" /etc/ssh/sshd_config.d/00-guardex-hardening.conf
    else
        rm -f /etc/ssh/sshd_config.d/00-guardex-hardening.conf
    fi
}

# ── disable SSH passwords only when a root public key is already installed ───
harden_ssh() {
    local authorized_keys="/root/.ssh/authorized_keys"
    if [ ! -s "$authorized_keys" ]; then
        warn "SSH key-only hardening skipped: ${authorized_keys} is empty or missing."
        return
    fi

    if ! ssh-keygen -l -f "$authorized_keys" >/dev/null 2>&1; then
        warn "SSH key-only hardening skipped: ${authorized_keys} contains no readable public key."
        return
    fi
    chown root:root /root/.ssh "$authorized_keys"
    chmod 0700 /root/.ssh
    chmod 0600 "$authorized_keys"

    local sshd_bin
    sshd_bin=$(command -v sshd 2>/dev/null || true)
    [ -n "$sshd_bin" ] || sshd_bin="/usr/sbin/sshd"
    [ -x "$sshd_bin" ] || die "OpenSSH server is required"

    if ! grep -Eiq '^[[:space:]]*Include[[:space:]]+.*/sshd_config\.d/' /etc/ssh/sshd_config; then
        warn "SSH key-only hardening skipped: sshd_config does not include sshd_config.d."
        return
    fi

    log "Disabling password-based SSH authentication..."
    install -d -m 0755 /etc/ssh/sshd_config.d
    local backup had_previous="no"
    backup=$(mktemp)
    if [ -e /etc/ssh/sshd_config.d/00-guardex-hardening.conf ]; then
        cp -p /etc/ssh/sshd_config.d/00-guardex-hardening.conf "$backup"
        had_previous="yes"
    fi
    install -m 0644 \
        "$INSTALL_DIR/ops/ssh/00-guardex-hardening.conf" \
        /etc/ssh/sshd_config.d/00-guardex-hardening.conf

    if ! "$sshd_bin" -t; then
        restore_ssh_dropin "$backup" "$had_previous"
        rm -f "$backup"
        die "Candidate SSH configuration is invalid; the previous configuration was restored"
    fi

    local effective
    if ! effective=$("$sshd_bin" -T -C "user=root,host=$(hostname),addr=127.0.0.1"); then
        restore_ssh_dropin "$backup" "$had_previous"
        rm -f "$backup"
        die "Could not evaluate SSH settings; the previous configuration was restored"
    fi
    if ! grep -qx 'passwordauthentication no' <<<"$effective" \
        || ! grep -qx 'kbdinteractiveauthentication no' <<<"$effective" \
        || ! grep -Eqx 'permitrootlogin (prohibit-password|without-password)' <<<"$effective" \
        || ! grep -qx 'pubkeyauthentication yes' <<<"$effective"; then
        restore_ssh_dropin "$backup" "$had_previous"
        rm -f "$backup"
        die "SSH key-only settings are not effective; the previous configuration was restored"
    fi
    if systemctl reload sshd.service 2>/dev/null; then
        :
    elif systemctl reload ssh.service 2>/dev/null; then
        :
    else
        restore_ssh_dropin "$backup" "$had_previous"
        rm -f "$backup"
        die "SSH service could not be reloaded; the previous configuration was restored"
    fi
    rm -f "$backup"
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
    printf "║  Reality PBK:     %-38s ║\n" "$REALITY_PUBLIC_KEY"
    printf "║  Reality SID:     %-38s ║\n" "$REALITY_SHORT_ID"
    printf "║  Inbound Port:    %-38s ║\n" "$XRAY_PORT"
    echo "╠══════════════════════════════════════════════════════════╣"
    case "$REGISTRATION_STATUS" in
        ok)        echo "║  ✓ Запрос отправлен → Admin Panel → Servers              ║" ;;
        duplicate) echo "║  ⚠ Уже ожидает подтверждения в Admin Panel               ║" ;;
        failed)    echo "║  ✗ Авторегистрация не удалась — добавь вручную           ║" ;;
        *)         echo "║  Добавь вручную: Admin Panel → Servers → Add server      ║" ;;
    esac
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    echo "Credentials are stored in root-only files under ${INSTALL_DIR}; secrets are not printed."
    echo "# Manage: cd ${INSTALL_DIR} && docker compose logs -f"
}

# ── auto-register with controller ─────────────────────────────────────────────
register_node() {
    [ -z "$CONTROLLER_URL" ] && return 0

    local ip; ip=$(curl -fsSL https://api4.my-ip.io/ip 2>/dev/null || curl -fsSL ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

    log "Registering node with controller at ${CONTROLLER_URL}..."
    local payload
    payload=$(cat <<PAYLOAD
{
  "host": "${ip}",
  "node_url": "http://${ip}:${AGENT_PORT}",
  "node_secret": "${AGENT_SECRET}",
  "reality_pbk": "${REALITY_PUBLIC_KEY}",
  "reality_short_id": "${REALITY_SHORT_ID}",
  "vless_port": ${XRAY_PORT},
  "inbound_tag": "${INBOUND_TAG}",
  "reality_sni": "www.google.com",
  "reality_flow": "xtls-rprx-vision"
}
PAYLOAD
)

    local http_code
    http_code=$(curl -sS -o /dev/null -w "%{http_code}" \
        -X POST "${CONTROLLER_URL}/v1/internal/node/register" \
        -H "Content-Type: application/json" \
        -H "X-Service-Token: ${INTERNAL_SERVICE_TOKEN}" \
        -d "$payload" 2>/dev/null) || true
    http_code="${http_code:-000}"

    if [ "$http_code" = "201" ]; then
        log "✓ Node registered — проверь Admin Panel → Servers"
        REGISTRATION_STATUS="ok"
    elif [ "$http_code" = "409" ]; then
        warn "Этот IP уже ожидает подтверждения в Admin Panel"
        REGISTRATION_STATUS="duplicate"
    else
        warn "Авторегистрация не удалась (HTTP $http_code) — добавь сервер вручную"
        REGISTRATION_STATUS="failed"
    fi
}

# ── main ──────────────────────────────────────────────────────────────────────
main() {
    require_root
    require_systemd

    install_prerequisites

    prompt_token
    install_docker
    generate_reality_keys
    clone_repo
    write_xray_config
    write_env
    install_management_firewall
    install_fail2ban
    harden_ssh
    start_containers
    register_node
    print_summary
}

main "$@"
