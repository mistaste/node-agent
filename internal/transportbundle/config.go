// Package transportbundle renders the shared TCP/443 ingress front door.
// UDP/443 intentionally remains outside this package and owned by TrustTunnel.
package transportbundle

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

var (
	hostPattern = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$`)
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type Config struct {
	PublicPort          int      `json:"public_port"`
	TrustTunnelHostname string   `json:"trusttunnel_hostname"`
	TrustTunnelPort     int      `json:"trusttunnel_port"`
	NaiveHostname       string   `json:"naive_hostname"`
	NaivePort           int      `json:"naive_port"`
	DecoyPort           int      `json:"decoy_port"`
	CertificateFile     string   `json:"certificate_file"`
	PrivateKeyFile      string   `json:"private_key_file"`
	ClientUUIDs         []string `json:"client_uuids"`
}

type Files struct{ HAProxy, Caddy []byte }

// NaiveCredential is deliberately domain-separated from TrustTunnel.
func NaiveCredential(nodeSecret, clientUUID string) (string, error) {
	nodeSecret = strings.TrimSpace(nodeSecret)
	clientUUID = strings.ToLower(strings.TrimSpace(clientUUID))
	if len(nodeSecret) < 32 {
		return "", errors.New("node secret must contain at least 32 characters")
	}
	if !uuidPattern.MatchString(clientUUID) {
		return "", errors.New("client UUID is invalid")
	}
	mac := hmac.New(sha256.New, []byte(nodeSecret))
	_, _ = mac.Write([]byte("guardex:naiveproxy:v1:" + clientUUID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func Build(nodeSecret string, cfg Config) (Files, error) {
	if cfg.PublicPort != 443 || !localPort(cfg.TrustTunnelPort) || !localPort(cfg.NaivePort) || !localPort(cfg.DecoyPort) {
		return Files{}, errors.New("transport bundle ports are invalid")
	}
	ttHost := normalizedHost(cfg.TrustTunnelHostname)
	naiveHost := normalizedHost(cfg.NaiveHostname)
	if ttHost == "" || naiveHost == "" || ttHost == naiveHost {
		return Files{}, errors.New("distinct DNS hostnames are required")
	}
	if !strings.HasPrefix(cfg.CertificateFile, "/") || !strings.HasPrefix(cfg.PrivateKeyFile, "/") {
		return Files{}, errors.New("certificate paths must be absolute")
	}
	clients := normalizeUUIDs(cfg.ClientUUIDs)
	if len(clients) == 0 {
		return Files{}, errors.New("at least one Naive client is required")
	}

	var users strings.Builder
	for _, id := range clients {
		password, err := NaiveCredential(nodeSecret, id)
		if err != nil {
			return Files{}, err
		}
		fmt.Fprintf(&users, "\t\t\tbasic_auth %s %s\n", id, password)
	}
	caddy := fmt.Sprintf(`{
	order forward_proxy before file_server
	auto_https disable_redirects
}

https://%s:%d {
	bind 127.0.0.1
	route {
		forward_proxy {
%s
			hide_ip
			hide_via
			probe_resistance
		}
	}
	log {
		output discard
	}
}

:%d {
	bind 127.0.0.1
	tls %s %s
	respond "OK" 200
}
`, naiveHost, cfg.NaivePort, users.String(), cfg.DecoyPort, cfg.CertificateFile, cfg.PrivateKeyFile)

	haproxy := fmt.Sprintf(`global
    log stdout format raw local0
    stats socket /run/guardex-haproxy-admin.sock mode 600 level admin

defaults
    mode tcp
    timeout connect 5s
    timeout client  1h
    timeout server  1h

frontend guardex_tls
    bind 0.0.0.0:%d
    tcp-request inspect-delay 5s
    tcp-request content accept if { req_ssl_hello_type 1 }
    acl sni_tt req.ssl_sni -i %s
    acl sni_naive req.ssl_sni -i %s
    use_backend trusttunnel if sni_tt
    use_backend naiveproxy if sni_naive
    default_backend https_decoy

backend trusttunnel
    server trusttunnel 127.0.0.1:%d check

backend naiveproxy
    server naiveproxy 127.0.0.1:%d check

backend https_decoy
    server decoy 127.0.0.1:%d check
`, cfg.PublicPort, ttHost, naiveHost, cfg.TrustTunnelPort, cfg.NaivePort, cfg.DecoyPort)
	return Files{HAProxy: []byte(haproxy), Caddy: []byte(caddy)}, nil
}

func localPort(port int) bool { return port >= 1024 && port <= 65535 && port != 443 }
func normalizedHost(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if net.ParseIP(value) != nil || len(value) > 253 || !hostPattern.MatchString(value) {
		return ""
	}
	return value
}
func normalizeUUIDs(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if uuidPattern.MatchString(value) {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
