package topology

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRelayCopyFailureIdentifiesSocketSideWithoutAddresses(t *testing.T) {
	for _, tc := range []struct {
		direction string
		op        string
		err       error
		want      string
	}{
		{"upstream_to_client_copy", "write", syscall.ECONNRESET, "upstream_to_client_copy_write_reset"},
		{"upstream_to_client_copy", "read", syscall.ECONNRESET, "upstream_to_client_copy_read_reset"},
		{"client_to_upstream_copy", "write", syscall.EPIPE, "client_to_upstream_copy_write_broken_pipe"},
		{"client_to_upstream_copy", "read", syscall.ETIMEDOUT, "client_to_upstream_copy_read_timeout"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			err := &net.OpError{Op: "readfrom", Err: fmt.Errorf("copy: %w", &net.OpError{
				Op: tc.op, Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.33"), Port: 54321}, Err: tc.err,
			})}
			if got := relayCopyFailureCode(tc.direction, err); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	if got := relayCopyFailureCode("upstream_to_client_copy", fmt.Errorf("unknown private data")); got != "upstream_to_client_copy" {
		t.Fatalf("unknown errors must not expose details: %q", got)
	}
}

func TestRelayDetailedFailuresRemainCompatibleWithDeployedController(t *testing.T) {
	r := NewTLSRelay()
	r.targets["node.example.com"] = "192.0.2.10:443"
	r.targetStats["node.example.com"] = &RelayTargetStats{ServerName: "node.example.com", Failures: map[string]uint64{}}
	for _, code := range []string{
		"upstream_handshake_timeout", "upstream_handshake_error",
		"upstream_to_client_copy_write_broken_pipe", "upstream_to_client_copy_read_reset",
		"client_to_upstream_copy_write_broken_pipe", "client_to_upstream_copy_read_timeout",
	} {
		r.recordFailure("node.example.com", code)
	}
	s := r.Snapshot()
	if len(s.Failures) != 2 || s.Failures["upstream_to_client_copy"] != 4 || s.Failures["client_to_upstream_copy"] != 2 {
		t.Fatalf("controller-incompatible categories: %v", s.Failures)
	}
	if s.LastFailure.Code != "client_to_upstream_copy" || len(s.Targets[0].Failures) != 2 {
		t.Fatalf("controller-incompatible last failure or target: %+v", s)
	}
}

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

func TestRelayStatsSeparateScannerNoiseFromRouteFailures(t *testing.T) {
	relay := NewTLSRelay()
	relay.targets["node.example.com"] = "192.0.2.10:443"
	relay.targetStats["node.example.com"] = &RelayTargetStats{
		ServerName: "node.example.com",
		Failures:   make(map[string]uint64),
	}

	relay.recordFailure("", "client_hello_invalid")
	relay.recordFailure("", "unknown_sni")
	if snapshot := relay.Snapshot(); snapshot.LastFailure != nil {
		t.Fatalf("scanner noise became actionable failure: %#v", snapshot.LastFailure)
	}

	relay.recordTargetAccepted("node.example.com")
	relay.recordDial("node.example.com", 12*time.Millisecond)
	relay.recordFailure("node.example.com", "upstream_dial_timeout")
	snapshot := relay.Snapshot()
	if snapshot.LastFailure == nil || snapshot.LastFailure.Code != "upstream_dial_timeout" || snapshot.LastFailure.ServerName != "node.example.com" {
		t.Fatalf("unexpected actionable failure: %#v", snapshot.LastFailure)
	}
	if snapshot.Failures["client_hello_invalid"] != 1 || snapshot.Failures["unknown_sni"] != 1 {
		t.Fatalf("scanner counters missing: %#v", snapshot.Failures)
	}
	if len(snapshot.Targets) != 1 || snapshot.Targets[0].Failures["upstream_dial_timeout"] != 1 || snapshot.Targets[0].UpstreamDialMs != 12 {
		t.Fatalf("unexpected target stats: %#v", snapshot.Targets)
	}
}

func TestRelaySnapshotIsImmutableAndSorted(t *testing.T) {
	relay := NewTLSRelay()
	for _, name := range []string{"z.example.com", "a.example.com"} {
		relay.targets[name] = "192.0.2.10:443"
		relay.targetStats[name] = &RelayTargetStats{ServerName: name, Failures: map[string]uint64{"upstream_dial_error": 1}}
	}
	snapshot := relay.Snapshot()
	if len(snapshot.Targets) != 2 || snapshot.Targets[0].ServerName != "a.example.com" || snapshot.Targets[1].ServerName != "z.example.com" {
		t.Fatalf("targets are not sorted: %#v", snapshot.Targets)
	}
	snapshot.Targets[0].Failures["upstream_dial_error"] = 99
	if relay.targetStats["a.example.com"].Failures["upstream_dial_error"] != 1 {
		t.Fatal("snapshot shares mutable failure counters")
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
