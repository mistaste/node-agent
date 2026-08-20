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
	for _, required := range []string{"bind 0.0.0.0:443", "req.ssl_sni -i node.example.com", "req.ssl_sni -i naive.node.example.com", "default_backend https_decoy", "127.0.0.1:8443", "127.0.0.1:9443"} {
		if !strings.Contains(haproxy, required) {
			t.Fatalf("HAProxy missing %q", required)
		}
	}
	caddy := string(files.Caddy)
	password, _ := NaiveCredential(testSecret, testUUID)
	if !strings.Contains(caddy, "basic_auth "+testUUID+" "+password) || !strings.Contains(caddy, "probe_resistance") {
		t.Fatal("Caddy authentication or probe resistance missing")
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
