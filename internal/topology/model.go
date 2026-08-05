package topology

import "net/netip"

const SchemaVersion = 1

type Role string

const (
	RoleIngress Role = "ingress"
	RoleExit    Role = "exit"
	RoleRelay   Role = "relay"
)

// DesiredState contains public routing intent only. WireGuard private keys
// are generated and retained locally in root-owned files.
type DesiredState struct {
	SchemaVersion int       `json:"schema_version"`
	Revision      int64     `json:"revision"`
	Role          Role      `json:"role"`
	Enabled       bool      `json:"enabled"`
	Backbone      *Backbone `json:"backbone,omitempty"`
	Relay         *Relay    `json:"relay,omitempty"`
}

type Backbone struct {
	InterfaceName     string         `json:"interface_name"`
	TunnelAddress     netip.Prefix   `json:"tunnel_address"`
	PeerTunnelAddress netip.Addr     `json:"peer_tunnel_address"`
	PeerPublicKey     string         `json:"peer_public_key"`
	PeerEndpoint      netip.AddrPort `json:"peer_endpoint"`
	ListenPort        int            `json:"listen_port"`
	IngressUID        uint32         `json:"ingress_uid,omitempty"`
	EgressInterface   string         `json:"egress_interface,omitempty"`
}

type Relay struct {
	IngressAddress netip.Addr `json:"ingress_address"`
	IngressPort    int        `json:"ingress_port"`
	TCPEnabled     bool       `json:"tcp_enabled"`
	UDPEnabled     bool       `json:"udp_enabled"`
}
