package topology

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	ErrUnsafeDesiredState = errors.New("unsafe topology desired state")
	interfacePattern      = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
	wgKeyPattern          = regexp.MustCompile(`^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$`)
)

func Validate(state DesiredState) error {
	if state.SchemaVersion != SchemaVersion || state.Revision < 1 {
		return fmt.Errorf("%w: unsupported schema or revision", ErrUnsafeDesiredState)
	}
	if !state.Enabled {
		if state.Backbone != nil || state.Relay != nil {
			return fmt.Errorf("%w: disabled state must be an empty tombstone", ErrUnsafeDesiredState)
		}
		return nil
	}
	switch state.Role {
	case RoleIngress, RoleExit:
		if state.Backbone == nil || state.Relay != nil {
			return fmt.Errorf("%w: ingress/exit requires only a backbone", ErrUnsafeDesiredState)
		}
		return validateBackbone(state.Role, *state.Backbone)
	case RoleRelay:
		if state.Relay == nil || state.Backbone != nil {
			return fmt.Errorf("%w: relay requires only a fixed relay route", ErrUnsafeDesiredState)
		}
		return validateRelay(*state.Relay)
	default:
		return fmt.Errorf("%w: unknown role", ErrUnsafeDesiredState)
	}
}

func validateBackbone(role Role, value Backbone) error {
	if !interfacePattern.MatchString(value.InterfaceName) || value.InterfaceName == "lo" ||
		!value.TunnelAddress.IsValid() || !value.TunnelAddress.Addr().IsPrivate() ||
		!value.TunnelAddress.Addr().Is4() || !value.PeerTunnelAddress.IsValid() ||
		!value.PeerTunnelAddress.IsPrivate() || !value.PeerTunnelAddress.Is4() ||
		value.TunnelAddress.Addr() == value.PeerTunnelAddress ||
		!value.TunnelAddress.Contains(value.PeerTunnelAddress) ||
		!wgKeyPattern.MatchString(strings.TrimSpace(value.PeerPublicKey)) ||
		!value.PeerEndpoint.IsValid() || !value.PeerEndpoint.Addr().IsGlobalUnicast() ||
		value.PeerEndpoint.Addr().IsPrivate() || value.ListenPort < 1 || value.ListenPort > 65535 {
		return fmt.Errorf("%w: invalid backbone", ErrUnsafeDesiredState)
	}
	if role == RoleIngress {
		if value.IngressUID < 100 || value.IngressUID > 65535 || value.EgressInterface != "" {
			return fmt.Errorf("%w: ingress must identify only its endpoint uid", ErrUnsafeDesiredState)
		}
	} else if !interfacePattern.MatchString(value.EgressInterface) || value.IngressUID != 0 {
		return fmt.Errorf("%w: exit must name only its public egress", ErrUnsafeDesiredState)
	}
	return nil
}

func validateRelay(value Relay) error {
	if !value.IngressAddress.IsValid() || !value.IngressAddress.Is4() || !value.IngressAddress.IsGlobalUnicast() ||
		value.IngressAddress.IsPrivate() || value.IngressPort != 443 ||
		(!value.TCPEnabled && !value.UDPEnabled) {
		return fmt.Errorf("%w: relay target must be one public ingress on 443", ErrUnsafeDesiredState)
	}
	return nil
}
