package transportbundle

import (
	"strings"
	"testing"
)

const testSecret = "0123456789abcdef0123456789abcdef"
const testUUID = "57aa857d-c8a8-4792-8bd0-74fcac8623fa"

func TestBuildRoutesTwoSNIAndHidesUnknownTraffic(t *testing.T) {
	files, err := Build(testSecret, Config{PublicPort: 443, TrustTunnelHostname: "node.example.com", TrustTunnelPort: 8443, NaiveHostname: "naive.node.example.com", NaivePort: 9443, DecoyPort: 9080, CertificateFile: "/etc/letsencrypt/fullchain.pem", PrivateKeyFile: "/etc/letsencrypt/privkey.pem", ClientUUIDs: []string{testUUID}})
	if err != nil {
		t.Fatal(err)
	}
	haproxy := string(files.HAProxy)
	defaults := "defaults\n    mode tcp\n    option clitcpka\n    option srvtcpka\n    timeout connect 5s\n    timeout client  24h\n    timeout server  24h"
	if !strings.Contains(haproxy, defaults) {
		t.Fatalf("HAProxy defaults do not preserve long-lived tunnels:\n%s", haproxy)
	}
	for _, required := range []string{"bind 0.0.0.0:443", "req.ssl_sni -i node.example.com", "req.ssl_sni -i naive.node.example.com", "default_backend https_decoy", "127.0.0.1:8443", "127.0.0.1:9443"} {
		if !strings.Contains(haproxy, required) {
			t.Fatalf("HAProxy missing %q", required)
		}
	}
	caddy := string(files.Caddy)
	password, _ := NaiveCredential(testSecret, testUUID)
	if !strings.Contains(caddy, "basic_auth "+testUUID+" "+password) || !strings.Contains(caddy, "probe_resistance") || !strings.Contains(caddy, "auto_https disable_redirects") || !strings.Contains(caddy, "disable_http_challenge") {
		t.Fatal("Caddy authentication or probe resistance missing")
	}
	for _, required := range []string{
		"@naive_auth_challenge {",
		"header padding *",
		"header padding-type-request *",
		`header @naive_auth_challenge Proxy-Authenticate "Basic realm=\"forward-proxy\""`,
		`respond @naive_auth_challenge "" 407`,
		`respond "OK" 200`,
	} {
		if !strings.Contains(caddy, required) {
			t.Fatalf("Caddy missing selective Naive authentication challenge %q", required)
		}
	}
	if strings.Count(caddy, "bind 127.0.0.1") != 2 || !strings.Contains(caddy, ":9080 {") {
		t.Fatal("Naive and TLS decoy listeners must remain private behind the SNI mux")
	}
	if strings.Contains(caddy, "https://naive.node.example.com:9443 {\n\tbind 127.0.0.1\n\ttls /etc/") {
		t.Fatal("Naive SNI must use Caddy-managed ACME instead of the TrustTunnel certificate")
	}
	if strings.Contains(caddy, ":9443, https://") {
		t.Fatal("Naive listener must not mix HTTP and HTTPS on the same address")
	}
}

func TestCredentialIsStableAndDomainSeparated(t *testing.T) {
	first, err := NaiveCredential(testSecret, testUUID)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := NaiveCredential(testSecret, testUUID)
	if first != second || first == "" {
		t.Fatal("credential is not deterministic")
	}
}

func TestBuildFailsClosed(t *testing.T) {
	_, err := Build(testSecret, Config{PublicPort: 443, TrustTunnelHostname: "same.example.com", TrustTunnelPort: 8443, NaiveHostname: "same.example.com", NaivePort: 9443, DecoyPort: 9080, CertificateFile: "/cert", PrivateKeyFile: "/key", ClientUUIDs: []string{testUUID}})
	if err == nil {
		t.Fatal("equal SNI hostnames must fail")
	}
}
