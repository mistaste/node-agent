package config

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	XrayGRPCAddr         string
	ListenAddr           string
	Secret               string
	DefaultInboundTag    string
	MetricsInterval      time.Duration
	ControllerURL        string
	NodeID               string
	InternalServiceToken string
	UsersFile            string
	ResyncInterval       time.Duration
	Version              string
	RepoDir              string
	UpdateRef            string
}

func Load() *Config {
	return &Config{
		XrayGRPCAddr:         getenv("XRAY_GRPC_ADDR", "127.0.0.1:10085"),
		ListenAddr:           getenv("AGENT_LISTEN_ADDR", "0.0.0.0:8080"),
		Secret:               getenv("AGENT_SECRET", "change-me-secret"),
		DefaultInboundTag:    getenv("XRAY_INBOUND_TAG", "vless-in"),
		MetricsInterval:      parseDuration(getenv("METRICS_INTERVAL", "15s")),
		ControllerURL:        getenv("CONTROLLER_URL", ""),
		NodeID:               getenv("NODE_ID", ""),
		InternalServiceToken: getenv("INTERNAL_SERVICE_TOKEN", ""),
		UsersFile:            getenv("USERS_FILE", "/data/users.json"),
		ResyncInterval:       parseDuration(getenv("RESYNC_INTERVAL", "30s")),
		Version:              getenv("AGENT_VERSION", "git"),
		RepoDir:              getenv("AGENT_REPO_DIR", "/opt/guardex-node"),
		UpdateRef:            getenv("AGENT_UPDATE_REF", "master"),
	}
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
	if c.Version != "" && c.Version != "git" {
		return c.Version
	}
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
