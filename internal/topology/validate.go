package topology

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

var (
	ErrUnsafeDesiredState = errors.New("unsafe topology desired state")
	interfacePattern      = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
	wgKeyPattern          = regexp.MustCompile(`^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$`)
	hostnamePattern       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	uuidPattern           = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

func Validate(state DesiredState) error {
	if state.SchemaVersion != SchemaVersion || state.Revision < 1 {
		return fmt.Errorf("%w: unsupported schema or revision", ErrUnsafeDesiredState)
	}
	if len(state.ExitProbes) > 16 {
		return fmt.Errorf("%w: too many exit probes", ErrUnsafeDesiredState)
	}
	if !state.Enabled {
		if state.Backbone != nil || state.Relay != nil || len(state.ExitProbes) != 0 {
			return fmt.Errorf("%w: disabled state must be an empty tombstone", ErrUnsafeDesiredState)
		}
		return nil
	}
	switch state.Role {
	case RoleIngress, RoleExit:
		if state.Backbone == nil || state.Relay != nil {
			return fmt.Errorf("%w: ingress/exit requires only a backbone", ErrUnsafeDesiredState)
		}
		if state.Role == RoleExit && len(state.ExitProbes) != 0 {
			return fmt.Errorf("%w: exit cannot receive exit probes", ErrUnsafeDesiredState)
		}
		if err := validateExitProbes(state.ExitProbes); err != nil {
			return err
		}
		return validateBackbone(state.Role, *state.Backbone)
	case RoleRelay:
		if state.Relay == nil || state.Backbone != nil || len(state.ExitProbes) != 0 {
			return fmt.Errorf("%w: relay requires only a fixed relay route", ErrUnsafeDesiredState)
		}
		return validateRelay(*state.Relay)
	default:
		return fmt.Errorf("%w: unknown role", ErrUnsafeDesiredState)
	}
}

func validateExitProbes(probes []ExitProbe) error {
	seen := make(map[string]struct{}, len(probes))
	for _, probe := range probes {
		id := strings.ToLower(strings.TrimSpace(probe.ExitServerID))
		if !uuidPattern.MatchString(id) || !probe.Endpoint.IsValid() ||
			!usablePublicIPv4(probe.Endpoint.Addr()) || probe.Endpoint.Port() == 0 {
			return fmt.Errorf("%w: invalid exit probe", ErrUnsafeDesiredState)
		}
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("%w: duplicate exit probe", ErrUnsafeDesiredState)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func validateBackbone(role Role, value Backbone) error {
	if !interfacePattern.MatchString(value.InterfaceName) || value.InterfaceName == "lo" ||
		len(value.AdditionalPeers) > 255 ||
		!value.TunnelAddress.IsValid() || !value.TunnelAddress.Addr().IsPrivate() ||
		!value.TunnelAddress.Addr().Is4() || !value.PeerTunnelAddress.IsValid() ||
		!value.PeerTunnelAddress.IsPrivate() || !value.PeerTunnelAddress.Is4() ||
		value.TunnelAddress.Addr() == value.PeerTunnelAddress ||
		value.TunnelAddress.Bits() != 30 ||
		!value.TunnelAddress.Contains(value.PeerTunnelAddress) ||
		!wgKeyPattern.MatchString(strings.TrimSpace(value.PeerPublicKey)) ||
		!value.PeerEndpoint.IsValid() || !usablePublicIPv4(value.PeerEndpoint.Addr()) ||
		value.ListenPort < 1 || value.ListenPort > 65535 {
		return fmt.Errorf("%w: invalid backbone", ErrUnsafeDesiredState)
	}
	if role == RoleIngress {
		if value.IngressUID < 100 || value.IngressUID > 65535 || value.EgressInterface != "" || len(value.AdditionalPeers) != 0 {
			return fmt.Errorf("%w: ingress must identify only its endpoint uid", ErrUnsafeDesiredState)
		}
	} else if !interfacePattern.MatchString(value.EgressInterface) || value.IngressUID != 0 {
		return fmt.Errorf("%w: exit must name only its public egress", ErrUnsafeDesiredState)
	}
	seenKeys := map[string]struct{}{strings.TrimSpace(value.PeerPublicKey): {}}
	seenAddresses := map[string]struct{}{value.TunnelAddress.String(): {}}
	for _, peer := range value.AdditionalPeers {
		if !validBackbonePair(peer.TunnelAddress, peer.PeerTunnelAddress) ||
			!wgKeyPattern.MatchString(strings.TrimSpace(peer.PeerPublicKey)) ||
			!peer.PeerEndpoint.IsValid() || !usablePublicIPv4(peer.PeerEndpoint.Addr()) ||
			peer.PeerEndpoint.Port() != uint16(value.ListenPort) {
			return fmt.Errorf("%w: invalid additional backbone peer", ErrUnsafeDesiredState)
		}
		key := strings.TrimSpace(peer.PeerPublicKey)
		if _, duplicate := seenKeys[key]; duplicate {
			return fmt.Errorf("%w: duplicate backbone peer", ErrUnsafeDesiredState)
		}
		if _, duplicate := seenAddresses[peer.TunnelAddress.String()]; duplicate {
			return fmt.Errorf("%w: duplicate backbone address", ErrUnsafeDesiredState)
		}
		seenKeys[key] = struct{}{}
		seenAddresses[peer.TunnelAddress.String()] = struct{}{}
	}
	return nil
}

func validBackbonePair(own netip.Prefix, peer netip.Addr) bool {
	return own.IsValid() && own.Addr().IsPrivate() && own.Addr().Is4() &&
		peer.IsValid() && peer.IsPrivate() && peer.Is4() && own.Bits() == 30 &&
		own.Addr() != peer && own.Contains(peer)
}

func validateRelay(value Relay) error {
	if len(value.Targets) > 0 {
		if !value.TCPEnabled || value.UDPEnabled || len(value.Targets) > 256 {
			return fmt.Errorf("%w: SNI relay must be TCP-only and bounded", ErrUnsafeDesiredState)
		}
		seen := make(map[string]struct{}, len(value.Targets))
		for _, target := range value.Targets {
			name := strings.ToLower(strings.TrimSpace(target.ServerName))
			if !hostnamePattern.MatchString(name) || !usablePublicIPv4(target.IngressAddress) || target.IngressPort != 443 {
				return fmt.Errorf("%w: invalid SNI relay target", ErrUnsafeDesiredState)
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("%w: duplicate SNI relay target", ErrUnsafeDesiredState)
			}
			seen[name] = struct{}{}
		}
		return nil
	}
	if !usablePublicIPv4(value.IngressAddress) || value.IngressPort != 443 ||
		(!value.TCPEnabled && !value.UDPEnabled) {
		return fmt.Errorf("%w: relay target must be one public ingress on 443", ErrUnsafeDesiredState)
	}
	return nil
}
