package topology

import (
	"crypto/tls"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestReadClientHelloExtractsOnlyAllowlistedSNI(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		tlsClient := tls.Client(client, &tls.Config{ServerName: "node.example.com", InsecureSkipVerify: true})
		_ = tlsClient.Handshake()
		_ = tlsClient.Close()
	}()
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	raw, name, err := readClientHello(server)
	if err != nil {
		t.Fatal(err)
	}
	if name != "node.example.com" || len(raw) < 5 || raw[0] != 22 {
		t.Fatalf("unexpected ClientHello result name=%q bytes=%d", name, len(raw))
	}
	_ = server.Close()
	<-done
}

func TestValidateMultiIngressExitAndSNIRelay(t *testing.T) {
	exit := backboneState(RoleExit)
	// EXIT and ingress sockets are independent. A provider may require the
	// shared EXIT endpoint on UDP 443 while ingress peers retain their own
	// non-conflicting WireGuard listen port.
	exit.Backbone.ListenPort = 443
	exit.Backbone.AdditionalPeers = []BackbonePeer{{
		TunnelAddress:     mustPrefix("10.92.0.2/30"),
		PeerTunnelAddress: mustAddr("10.92.0.1"),
		PeerPublicKey:     "X6iCcvOewJyIITUO42yCLKvKHTNBolQObM+7U/NU7zk=",
		PeerEndpoint:      mustAddrPort("1.1.1.1:51821"),
	}}
	if err := Validate(exit); err != nil {
		t.Fatalf("multi-peer exit rejected: %v", err)
	}
	relay := DesiredState{SchemaVersion: 1, Revision: 3, Role: RoleRelay, Enabled: true, Relay: &Relay{
		IngressAddress: mustAddr("93.184.216.34"), IngressPort: 443, TCPEnabled: true,
		Targets: []RelayTarget{
			{ServerName: "a.example.com", IngressAddress: mustAddr("93.184.216.34"), IngressPort: 443},
			{ServerName: "b.example.com", IngressAddress: mustAddr("1.1.1.1"), IngressPort: 443},
		},
	}}
	if err := Validate(relay); err != nil {
		t.Fatalf("SNI relay rejected: %v", err)
	}
	rules, err := RenderNFTables(relay)
	if err != nil {
		t.Fatal(err)
	}
	if !containsAll(rules, "tcp dport 443 redirect to :10443", "tcp dport 10443 ct status dnat accept", "tcp dport 10443 reject") {
		t.Fatalf("bounded relay rules missing: %s", rules)
	}
}

func mustPrefix(value string) netip.Prefix     { return netip.MustParsePrefix(value) }
func mustAddr(value string) netip.Addr         { return netip.MustParseAddr(value) }
func mustAddrPort(value string) netip.AddrPort { return netip.MustParseAddrPort(value) }
func containsAll(value string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(value, part) {
			return false
		}
	}
	return true
}
