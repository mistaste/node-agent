// Package trusttunnel owns Guardex's deterministic TrustTunnel endpoint files.
// It deliberately does not share Xray's dynamic-inbound representation.
package trusttunnel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	hostPattern = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$`)
)

type Endpoint struct {
	Port            int
	Hostname        string
	CertificateFile string
	PrivateKeyFile  string
	ClientUUIDs     []string
	EnableHTTP1     bool
	EnableHTTP2     bool
	EnableHTTP3     bool
	IPv6Available   bool
	MetricsPort     int
}

type Files struct {
	Settings    []byte
	Hosts       []byte
	Credentials []byte
}

// Credential derives a node-scoped password without persisting or transporting
// an additional secret. Backend and node can reproduce it from the already
// provisioned node secret, while compromise of one node does not expose others.
func Credential(nodeSecret, clientUUID string) (string, error) {
	clientUUID = strings.ToLower(strings.TrimSpace(clientUUID))
	if len(strings.TrimSpace(nodeSecret)) < 32 {
		return "", errors.New("node secret must contain at least 32 characters")
	}
	if !uuidPattern.MatchString(clientUUID) {
		return "", errors.New("client UUID is invalid")
	}
	mac := hmac.New(sha256.New, []byte(nodeSecret))
	_, _ = mac.Write([]byte("guardex:trusttunnel:v1:" + clientUUID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func BuildFiles(root, nodeSecret string, endpoint Endpoint) (Files, error) {
	if endpoint.Port < 1 || endpoint.Port > 65535 {
		return Files{}, errors.New("endpoint port is invalid")
	}
	host := strings.ToLower(strings.TrimSpace(endpoint.Hostname))
	if net.ParseIP(host) != nil || !hostPattern.MatchString(host) || len(host) > 253 {
		return Files{}, errors.New("endpoint hostname must be a DNS name")
	}
	if !endpoint.EnableHTTP1 && !endpoint.EnableHTTP2 && !endpoint.EnableHTTP3 {
		return Files{}, errors.New("at least one endpoint protocol is required")
	}
	cert := cleanManagedPath(root, endpoint.CertificateFile)
	key := cleanManagedPath(root, endpoint.PrivateKeyFile)
	if cert == "" || key == "" {
		return Files{}, errors.New("certificate paths must stay inside the managed root")
	}

	clients := normalizeUUIDs(endpoint.ClientUUIDs)
	var credentials strings.Builder
	for _, client := range clients {
		password, err := Credential(nodeSecret, client)
		if err != nil {
			return Files{}, err
		}
		fmt.Fprintf(&credentials, "[[client]]\nusername = %s\npassword = %s\n\n", quote(client), quote(password))
	}
	if len(clients) == 0 {
		// The endpoint refuses a public listener without credentials. A staged
		// route must remain stopped until at least one active profile exists.
		return Files{}, errors.New("endpoint requires at least one active client")
	}

	var protocols strings.Builder
	protocols.WriteString("[listen_protocols]\n")
	if endpoint.EnableHTTP1 {
		protocols.WriteString("[listen_protocols.http1]\n\n")
	}
	if endpoint.EnableHTTP2 {
		protocols.WriteString("[listen_protocols.http2]\n\n")
	}
	if endpoint.EnableHTTP3 {
		protocols.WriteString("[listen_protocols.quic]\n\n")
	}
	metricsPort := endpoint.MetricsPort
	if metricsPort == 0 {
		metricsPort = 1987
	}
	if metricsPort < 1024 || metricsPort > 65535 {
		return Files{}, errors.New("metrics port is invalid")
	}
	settings := fmt.Sprintf("listen_address = %s\nipv6_available = %t\nallow_private_network_connections = false\ncredentials_file = %s\ntls_handshake_timeout_secs = 10\nclient_listener_timeout_secs = 600\nconnection_establishment_timeout_secs = 30\ntcp_connections_timeout_secs = 86400\nudp_connections_timeout_secs = 300\nspeedtest_enable = false\nping_enable = true\nauth_failure_status_code = 405\n\n%s[forward_protocol]\ndirect = {}\n\n[metrics]\naddress = %s\nrequest_timeout_secs = 3\n",
		quote("0.0.0.0:"+strconv.Itoa(endpoint.Port)), endpoint.IPv6Available,
		quote(filepath.Join(root, "credentials.toml")), protocols.String(), quote("127.0.0.1:"+strconv.Itoa(metricsPort)))
	hosts := fmt.Sprintf("[[main_hosts]]\nhostname = %s\ncert_chain_path = %s\nprivate_key_path = %s\n",
		quote(host), quote(cert), quote(key))
	return Files{Settings: []byte(settings), Hosts: []byte(hosts), Credentials: []byte(credentials.String())}, nil
}

func normalizeUUIDs(values []string) []string {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if uuidPattern.MatchString(value) {
			unique[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func cleanManagedPath(root, value string) string {
	root = filepath.Clean(strings.TrimSpace(root))
	value = filepath.Clean(strings.TrimSpace(value))
	if root == "." || !filepath.IsAbs(root) || !filepath.IsAbs(value) {
		return ""
	}
	relative, err := filepath.Rel(root, value)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return ""
	}
	return value
}

func quote(value string) string {
	return strconv.Quote(value)
}
