package topology

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

const testPeerKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func backboneState(role Role) DesiredState {
	b := &Backbone{InterfaceName: "gxwg0", TunnelAddress: netip.MustParsePrefix("10.91.0.1/30"), PeerTunnelAddress: netip.MustParseAddr("10.91.0.2"), PeerPublicKey: testPeerKey, PeerEndpoint: netip.MustParseAddrPort("93.184.216.34:51820"), ListenPort: 51820}
	if role == RoleIngress {
		b.IngressUID = 65532
	} else {
		b.EgressInterface = "eth0"
	}
	return DesiredState{SchemaVersion: 1, Revision: 1, Role: role, Enabled: true, Backbone: b}
}

func TestIngressRulesAreFailClosed(t *testing.T) {
	rules, err := RenderNFTables(backboneState(RoleIngress))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rules, `meta skuid 65532 ip daddr 93.184.216.34 udp dport 51820 accept`) ||
		!strings.Contains(rules, `meta skuid 65532 oifname "gxwg0" accept`) ||
		!strings.Contains(rules, `meta skuid 65532 reject`) {
		t.Fatalf("missing fail-closed ingress rules:\n%s", rules)
	}
}

func TestRelayHasOnlyFixed443Destination(t *testing.T) {
	state := DesiredState{SchemaVersion: 1, Revision: 2, Role: RoleRelay, Enabled: true, Relay: &Relay{IngressAddress: netip.MustParseAddr("93.184.216.34"), IngressPort: 443, TCPEnabled: true, UDPEnabled: true}}
	rules, err := RenderNFTables(state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(rules, "dnat ip to 93.184.216.34:443") != 2 || strings.Contains(rules, "redirect") {
		t.Fatalf("relay is not fixed:\n%s", rules)
	}
	if !strings.Contains(rules, "ct state established,related accept") {
		t.Fatalf("relay would drop return packets without conntrack accept:\n%s", rules)
	}
	if !strings.Contains(rules, "\n  reject\n") ||
		strings.Contains(rules, "ip daddr 93.184.216.34 masquerade") {
		t.Fatalf("relay permits traffic outside the fixed protocol/port:\n%s", rules)
	}
	state.Relay.IngressPort = 8443
	if _, err := RenderNFTables(state); !errors.Is(err, ErrUnsafeDesiredState) {
		t.Fatalf("unsafe relay accepted: %v", err)
	}
	state.Relay.IngressPort = 443
	state.Relay.IngressAddress = netip.MustParseAddr("203.0.113.10")
	if _, err := RenderNFTables(state); !errors.Is(err, ErrUnsafeDesiredState) {
		t.Fatalf("reserved relay accepted: %v", err)
	}
}

func TestBackboneRequiresPointToPointCIDR(t *testing.T) {
	state := backboneState(RoleIngress)
	state.Backbone.TunnelAddress = netip.MustParsePrefix("10.91.0.1/24")
	if _, err := RenderNFTables(state); !errors.Is(err, ErrUnsafeDesiredState) {
		t.Fatalf("non-/30 backbone accepted: %v", err)
	}

	state = backboneState(RoleIngress)
	state.Backbone.PeerTunnelAddress = netip.MustParseAddr("10.91.0.6")
	if _, err := RenderNFTables(state); !errors.Is(err, ErrUnsafeDesiredState) {
		t.Fatalf("peer outside /30 backbone accepted: %v", err)
	}
}

func TestDisabledStateIsEmptyTombstone(t *testing.T) {
	rules, err := RenderNFTables(DesiredState{SchemaVersion: 1, Revision: 3, Role: RoleRelay})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rules, "dnat") || strings.Contains(rules, "masquerade") {
		t.Fatalf("disabled topology retained forwarding:\n%s", rules)
	}
}

func TestRendererRejectsUnresolvedExitInterface(t *testing.T) {
	state := backboneState(RoleExit)
	state.Backbone.EgressInterface = "auto"
	if _, err := RenderNFTables(state); !errors.Is(err, ErrUnsafeDesiredState) {
		t.Fatalf("unresolved exit interface accepted: %v", err)
	}
}
