package topology

import (
	"fmt"
	"strings"
)

const TableName = "guardex_transport"

// RenderNFTables returns the Guardex-owned nft table. It never mutates an
// operator/distribution table and each forwarding role fails closed.
func RenderNFTables(state DesiredState) (string, error) {
	if err := Validate(state); err != nil {
		return "", err
	}
	body := []string{"table inet " + TableName + " {", " chain forward { type filter hook forward priority -5; policy accept;"}
	if !state.Enabled {
		return strings.Join(append(body, " }", "}"), "\n") + "\n", nil
	}
	switch state.Role {
	case RoleIngress:
		b := state.Backbone
		body = append(body,
			" }", " chain output { type filter hook output priority -5; policy accept;",
			fmt.Sprintf("  meta skuid %d oifname %q accept", b.IngressUID, b.InterfaceName),
			fmt.Sprintf("  meta skuid %d reject", b.IngressUID), " }", "}")
	case RoleExit:
		b := state.Backbone
		body = append(body,
			fmt.Sprintf("  iifname %q oifname %q accept", b.InterfaceName, b.EgressInterface),
			fmt.Sprintf("  iifname %q reject", b.InterfaceName), " }",
			" chain postrouting { type nat hook postrouting priority srcnat; policy accept;",
			fmt.Sprintf("  iifname %q oifname %q masquerade", b.InterfaceName, b.EgressInterface), " }", "}")
	case RoleRelay:
		r := state.Relay
		if r.TCPEnabled {
			body = append(body, fmt.Sprintf("  ip daddr %s tcp dport 443 accept", r.IngressAddress))
		}
		if r.UDPEnabled {
			body = append(body, fmt.Sprintf("  ip daddr %s udp dport 443 accept", r.IngressAddress))
		}
		body = append(body,
			fmt.Sprintf("  ip daddr %s reject", r.IngressAddress),
			" }", " chain prerouting { type nat hook prerouting priority dstnat; policy accept;")
		if r.TCPEnabled {
			body = append(body, fmt.Sprintf("  tcp dport 443 dnat to %s:%d", r.IngressAddress, r.IngressPort))
		}
		if r.UDPEnabled {
			body = append(body, fmt.Sprintf("  udp dport 443 dnat to %s:%d", r.IngressAddress, r.IngressPort))
		}
		body = append(body, " }", " chain postrouting { type nat hook postrouting priority srcnat; policy accept;")
		if r.TCPEnabled {
			body = append(body, fmt.Sprintf("  ip daddr %s tcp dport 443 masquerade", r.IngressAddress))
		}
		if r.UDPEnabled {
			body = append(body, fmt.Sprintf("  ip daddr %s udp dport 443 masquerade", r.IngressAddress))
		}
		body = append(body, " }", "}")
	}
	return strings.Join(body, "\n") + "\n", nil
}
