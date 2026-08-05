package trusttunnel

import (
	"bytes"
	"strings"
	"testing"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func TestCredentialIsDeterministicAndNodeScoped(t *testing.T) {
	uuid := "57aa857d-c8a8-4792-8bd0-74fcac8623fa"
	first, err := Credential(testSecret, uuid)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := Credential(testSecret, uuid)
	other, _ := Credential("abcdef0123456789abcdef0123456789", uuid)
	if first != second || first == other || len(first) < 32 {
		t.Fatal("credential derivation is not stable and node scoped")
	}
}

func TestBuildFilesIsStableAndContainsNoNodeSecret(t *testing.T) {
	endpoint := Endpoint{
		Port: 8443, Hostname: "edge.example.com",
		CertificateFile: "/etc/guardex/trusttunnel/certs/fullchain.pem",
		PrivateKeyFile:  "/etc/guardex/trusttunnel/certs/privkey.pem",
		ClientUUIDs:     []string{"57aa857d-c8a8-4792-8bd0-74fcac8623fa", "57aa857d-c8a8-4792-8bd0-74fcac8623fa"},
		EnableHTTP2:     true, EnableHTTP3: true, IPv6Available: true,
	}
	files, err := BuildFiles("/etc/guardex/trusttunnel", testSecret, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	all := bytes.Join([][]byte{files.Settings, files.Hosts, files.Credentials}, nil)
	if bytes.Contains(all, []byte(testSecret)) {
		t.Fatal("node secret leaked into generated files")
	}
	if strings.Count(string(files.Credentials), "[[client]]") != 1 {
		t.Fatalf("credentials were not deduplicated: %s", files.Credentials)
	}
	if !bytes.Contains(files.Settings, []byte("[listen_protocols.http2]")) || !bytes.Contains(files.Settings, []byte("[listen_protocols.quic]")) {
		t.Fatalf("protocol configuration missing: %s", files.Settings)
	}
	if bytes.Contains(files.Settings, []byte("[listen_protocols.http1]")) {
		t.Fatalf("HTTP/1 listener must stay disabled for Stage 1: %s", files.Settings)
	}
	for _, expected := range []string{
		"connection_establishment_timeout_secs = 30",
		"tcp_connections_timeout_secs = 86400",
		"udp_connections_timeout_secs = 300",
		"speedtest_enable = false",
		"ping_enable = false",
		"auth_failure_status_code = 405",
		"[metrics]",
		"address = \"127.0.0.1:1987\"",
	} {
		if !strings.Contains(string(files.Settings), expected) {
			t.Fatalf("Stage 1 TrustTunnel setting %q missing: %s", expected, files.Settings)
		}
	}
}

func TestBuildFilesRejectsEscapedPrivateKey(t *testing.T) {
	_, err := BuildFiles("/etc/guardex/trusttunnel", testSecret, Endpoint{
		Port: 8443, Hostname: "edge.example.com", EnableHTTP2: true,
		CertificateFile: "/etc/guardex/trusttunnel/certs/fullchain.pem",
		PrivateKeyFile:  "/tmp/stolen.pem",
		ClientUUIDs:     []string{"57aa857d-c8a8-4792-8bd0-74fcac8623fa"},
	})
	if err == nil {
		t.Fatal("escaped private key path was accepted")
	}
}
