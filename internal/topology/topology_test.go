package topology

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

const testPeerKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func backboneState(role Role) DesiredState {
	b := &Backbone{InterfaceName: "gxwg0", TunnelAddress: netip.MustParsePrefix("10.91.0.1/30"), PeerTunnelAddress: netip.MustParseAddr("10.91.0.2"), PeerPublicKey: testPeerKey, PeerEndpoint: netip.MustParseAddrPort("203.0.113.20:51820"), ListenPort: 51820}
	if role == RoleIngress {
		b.IngressInterface = "gxtt0"
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
	if !strings.Contains(rules, `iifname "gxtt0" oifname "gxwg0" accept`) || !strings.Contains(rules, `iifname "gxtt0" reject`) {
		t.Fatalf("missing fail-closed ingress rules:\n%s", rules)
	}
}

func TestRelayHasOnlyFixed443Destination(t *testing.T) {
	state := DesiredState{SchemaVersion: 1, Revision: 2, Role: RoleRelay, Enabled: true, Relay: &Relay{IngressAddress: netip.MustParseAddr("203.0.113.10"), IngressPort: 443, TCPEnabled: true, UDPEnabled: true}}
	rules, err := RenderNFTables(state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(rules, "dnat to 203.0.113.10:443") != 2 || strings.Contains(rules, "redirect") {
		t.Fatalf("relay is not fixed:\n%s", rules)
	}
	state.Relay.IngressPort = 8443
	if _, err := RenderNFTables(state); !errors.Is(err, ErrUnsafeDesiredState) {
		t.Fatalf("unsafe relay accepted: %v", err)
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
