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
		!strings.Contains(rules, `meta skuid 65532 oifname "lo" accept`) ||
		!strings.Contains(rules, `meta skuid 65532 oifname "gxwg0" accept`) ||
		!strings.Contains(rules, `meta skuid 65532 reject`) ||
		!strings.Contains(rules, `tcp dport 443 ct mark set 0x4758`) ||
		!strings.Contains(rules, `udp dport 443 ct mark set 0x4758`) ||
		!strings.Contains(rules, `ct mark 0x4758 meta mark set 0x4758`) {
		t.Fatalf("missing fail-closed ingress rules:\n%s", rules)
	}
}

func TestIngressReplyRoutingDoesNotAddUIDPublicEgressBypass(t *testing.T) {
	rules, err := RenderNFTables(backboneState(RoleIngress))
	if err != nil {
		t.Fatal(err)
	}
	const replyRule = "meta skuid 65532 meta l4proto udp ct direction reply ct state established ct mark 0x4758 ct original proto-dst 443 accept"
	if strings.Count(rules, replyRule) != 1 ||
		strings.Index(rules, replyRule) > strings.Index(rules, "meta skuid 65532 reject") {
		t.Fatal("missing/reordered narrow UDP return exception")
	}
	// The source-port policy is NOT a permission to originate traffic to WAN.
	if strings.Contains(rules, "udp sport 443 accept") ||
		strings.Contains(rules, "meta skuid 65532 ct mark 0x4758 accept") ||
		strings.Contains(rules, "meta skuid 65532 meta mark 0x4758 accept") ||
		strings.Contains(rules, "meta skuid 65532 ct state established accept") {
		t.Fatal("return exception must not allow unrelated/original-direction UID egress")
	}
	allowedUIDRules := 0
	for _, line := range strings.Split(rules, "\n") {
		if strings.Contains(line, "meta skuid 65532") && strings.HasSuffix(line, " accept") {
			allowedUIDRules++
		}
	}
	if allowedUIDRules != 4 {
		t.Fatalf("unexpected UID egress exception count: %d", allowedUIDRules)
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
