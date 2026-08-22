package config

import (
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	XrayGRPCAddr           string
	ListenAddr             string
	Secret                 string
	DefaultInboundTag      string
	MetricsInterval        time.Duration
	MetricsOnly            bool
	ControllerURL          string
	NodeID                 string
	InternalServiceToken   string
	UsersFile              string
	InboundsFile           string
	ResyncInterval         time.Duration
	Version                string
	XrayCoreVersion        string
	TrustTunnelEnabled     bool
	TrustTunnelProcessMode string
	TrustTunnelBinary      string
	TrustTunnelRoot        string
	TrustTunnelService     string
	TrustTunnelVersion     string
	TransportBundleEnabled bool
	TransportBundleRoot    string
	RepoDir                string
	UpdateRef              string
}

func Load() *Config {
	return &Config{
		XrayGRPCAddr:           getenv("XRAY_GRPC_ADDR", "127.0.0.1:10085"),
		ListenAddr:             getenv("AGENT_LISTEN_ADDR", "0.0.0.0:8080"),
		Secret:                 getenv("AGENT_SECRET", "change-me-secret"),
		DefaultInboundTag:      getenv("XRAY_INBOUND_TAG", "vless-in"),
		MetricsInterval:        parseDuration(getenv("METRICS_INTERVAL", "15s")),
		MetricsOnly:            parseBool(getenv("METRICS_ONLY", "false")),
		ControllerURL:          canonicalControllerURL(getenv("CONTROLLER_URL", "")),
		NodeID:                 getenv("NODE_ID", ""),
		InternalServiceToken:   getenv("INTERNAL_SERVICE_TOKEN", ""),
		UsersFile:              getenv("USERS_FILE", "/data/users.json"),
		InboundsFile:           getenv("INBOUNDS_FILE", "/data/inbounds.json"),
		ResyncInterval:         parseDuration(getenv("RESYNC_INTERVAL", "30s")),
		Version:                getenv("AGENT_VERSION", "git"),
		XrayCoreVersion:        getenv("XRAY_CORE_VERSION", "unknown"),
		TrustTunnelEnabled:     parseBool(getenv("TRUSTTUNNEL_ENABLED", "false")),
		TrustTunnelProcessMode: getenv("TRUSTTUNNEL_PROCESS_MODE", "managed"),
		TrustTunnelBinary:      getenv("TRUSTTUNNEL_BINARY", "/opt/trusttunnel/trusttunnel_endpoint"),
		TrustTunnelRoot:        getenv("TRUSTTUNNEL_ROOT", "/etc/guardex/trusttunnel"),
		TrustTunnelService:     getenv("TRUSTTUNNEL_SERVICE", "guardex-trusttunnel.service"),
		TrustTunnelVersion:     getenv("TRUSTTUNNEL_VERSION", "unknown"),
		TransportBundleEnabled: parseBool(getenv("TRANSPORT_BUNDLE_ENABLED", "false")),
		TransportBundleRoot:    getenv("TRANSPORT_BUNDLE_ROOT", "/data/transport-bundle"),
		RepoDir:                getenv("AGENT_REPO_DIR", "/opt/guardex-node"),
		UpdateRef:              getenv("AGENT_UPDATE_REF", "master"),
	}
}

func parseBool(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func canonicalControllerURL(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.TrimRight(trimmed, "/") == "https://api.guardex-vpn.com:2096" {
		return "https://api.guardex-vpn.com"
	}
	return trimmed
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseDuration(s string) time.Duration {
	if n, err := strconv.Atoi(s); err == nil {
		return time.Duration(n) * time.Second
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 15 * time.Second
	}
	return d
}

func (c *Config) AgentVersion() string {
	// The checked-out revision is authoritative for git-managed nodes. Older
	// deployments pinned AGENT_VERSION in .env, which made successfully updated
	// agents keep advertising the stale value forever.
	if out, err := exec.Command("git", "-C", c.RepoDir, "rev-parse", "--short", "HEAD").Output(); err == nil {
		if v := strings.TrimSpace(string(out)); v != "" {
			return v
		}
	}
	if c.Version != "" {
		return c.Version
	}
	return "unknown"
}

// AgentAPISecretValid prevents the privileged management API from starting
// with the documented placeholder or a trivially brute-forceable credential.
func (c *Config) AgentAPISecretValid() bool {
	secret := strings.TrimSpace(c.Secret)
	return len(secret) >= 32 && secret != "change-me-secret"
}

// ControllerPollingEnabled is true only when the complete mutually
// authenticated controller configuration is present and uses verified HTTPS.
func (c *Config) ControllerPollingEnabled() bool {
	secret := strings.TrimSpace(c.Secret)
	if strings.TrimSpace(c.ControllerURL) == "" || strings.TrimSpace(c.InternalServiceToken) == "" || secret == "" || secret == "change-me-secret" {
		return false
	}
	parsed, err := url.Parse(strings.TrimSpace(c.ControllerURL))
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil
}
