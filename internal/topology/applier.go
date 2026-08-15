package topology

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

const policyTable = "51820"

type commandRunner interface {
	Run(context.Context, []byte, string, ...string) error
}
type osRunner struct{}

func (osRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s failed: %w (%s)", filepath.Base(name), err, strings.TrimSpace(string(output)))
	}
	return nil
}

type Applier struct {
	root           string
	routeTablePath string
	ipForwardPath  string
	runner         commandRunner
}

func NewApplier(root string) (*Applier, error) {
	root = filepath.Clean(strings.TrimSpace(root))
	if !filepath.IsAbs(root) {
		return nil, errors.New("topology root must be absolute")
	}
	return &Applier{
		root: root, routeTablePath: "/proc/net/route",
		ipForwardPath: "/proc/sys/net/ipv4/ip_forward", runner: osRunner{},
	}, nil
}

func (a *Applier) PublicKey() (string, error) {
	private, err := a.ensurePrivateKey()
	if err != nil {
		return "", err
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(public), nil
}

func (a *Applier) Apply(ctx context.Context, state DesiredState) error {
	var err error
	state, err = a.resolveLocalState(state)
	if err != nil {
		return err
	}
	if err := Validate(state); err != nil {
		return err
	}
	current, _ := a.loadState()
	// A local unassigned tombstone has no controller revision namespace. It
	// must not prevent a newly created role from starting again at revision 1.
	if current.Role == "" && !current.Enabled {
		current = DesiredState{}
	}
	if current.Revision > state.Revision {
		return ErrUnsafeDesiredState
	}
	if current.Revision == state.Revision {
		oldJSON, _ := json.Marshal(current)
		newJSON, _ := json.Marshal(state)
		if bytes.Equal(oldJSON, newJSON) {
			return nil
		}
		return fmt.Errorf("%w: desired state changed without revision", ErrUnsafeDesiredState)
	}
	if !state.Enabled {
		if err := a.removeOwned(ctx, current); err != nil {
			return err
		}
		return a.saveState(state)
	}
	if current.Enabled && topologyOwnershipChanged(current, state) {
		// A role or interface transition must never retain the previous
		// Guardex-owned policy route, WireGuard device, or relay table. If the
		// replacement later fails, the node stays fail-closed and retries from
		// the last desired revision instead of running two topologies at once.
		if err := a.removeOwned(ctx, current); err != nil {
			return err
		}
	}
	var rollback func(context.Context)
	if state.Backbone != nil {
		rollback, err = a.applyWireGuard(ctx, state, current)
		if err != nil {
			return err
		}
	}
	forwardRollback, err := a.ensureDockerForwarding(ctx, state)
	if err != nil {
		if rollback != nil {
			rollback(ctx)
		}
		return err
	}
	rules, err := RenderNFTables(state)
	if err != nil {
		forwardRollback(ctx)
		if rollback != nil {
			rollback(ctx)
		}
		return err
	}
	transaction := ""
	if a.runner.Run(ctx, nil, "nft", "list", "table", "inet", TableName) == nil {
		transaction = "delete table inet " + TableName + "\n"
	}
	transaction += rules
	if err := a.runner.Run(ctx, []byte(transaction), "nft", "-c", "-f", "-"); err != nil {
		forwardRollback(ctx)
		if rollback != nil {
			rollback(ctx)
		}
		return err
	}
	if err := a.runner.Run(ctx, []byte(transaction), "nft", "-f", "-"); err != nil {
		forwardRollback(ctx)
		if rollback != nil {
			rollback(ctx)
		}
		return err
	}
	if err := a.saveState(state); err != nil {
		forwardRollback(ctx)
		if rollback != nil {
			rollback(ctx)
		}
		return err
	}
	a.removeDockerForwarding(ctx, missingForwardRules(dockerForwardRules(current), dockerForwardRules(state)))
	return nil
}

func (a *Applier) resolveLocalState(state DesiredState) (DesiredState, error) {
	if !state.Enabled || state.Role != RoleExit || state.Backbone == nil ||
		state.Backbone.EgressInterface != "auto" {
		return state, nil
	}
	name, err := defaultIPv4Interface(a.routeTablePath)
	if err != nil {
		return state, err
	}
	copy := *state.Backbone
	copy.EgressInterface = name
	state.Backbone = &copy
	return state, nil
}

func defaultIPv4Interface(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read default route: %w", err)
	}
	for index, line := range strings.Split(string(raw), "\n") {
		if index == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != "00000000" {
			continue
		}
		flags, parseErr := strconv.ParseUint(fields[3], 16, 32)
		if parseErr != nil || flags&0x1 == 0 || !interfacePattern.MatchString(fields[0]) || fields[0] == "lo" {
			continue
		}
		return fields[0], nil
	}
	return "", fmt.Errorf("%w: public IPv4 default interface is unavailable", ErrUnsafeDesiredState)
}

// RemoveUnassigned handles an empty controller assignment independently of
// its synthetic revision. Losing the database role must withdraw forwarding;
// an older empty revision can never be allowed to preserve a newer live route.
func (a *Applier) RemoveUnassigned(ctx context.Context) error {
	current, err := a.loadState()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if current.Role == "" && !current.Enabled && current.Revision >= 1 {
		return nil
	}
	if current.Enabled {
		if err := a.removeOwned(ctx, current); err != nil {
			return err
		}
	}
	revision := current.Revision + 1
	if revision < 1 {
		revision = 1
	}
	return a.saveState(DesiredState{SchemaVersion: SchemaVersion, Revision: revision})
}

func topologyOwnershipChanged(current, next DesiredState) bool {
	if current.Role != next.Role {
		return true
	}
	if current.Backbone == nil || next.Backbone == nil {
		return current.Backbone != next.Backbone
	}
	return current.Backbone.InterfaceName != next.Backbone.InterfaceName
}

func (a *Applier) applyWireGuard(ctx context.Context, state, previous DesiredState) (func(context.Context), error) {
	b := state.Backbone
	private, err := a.ensurePrivateKey()
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(a.root, "wireguard.key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(private)+"\n"), 0600); err != nil {
		return nil, err
	}
	created := false
	if a.runner.Run(ctx, nil, "ip", "link", "show", "dev", b.InterfaceName) != nil {
		if err := a.runner.Run(ctx, nil, "ip", "link", "add", "dev", b.InterfaceName, "type", "wireguard"); err != nil {
			return nil, err
		}
		created = true
	}
	rollback := func(rollbackCtx context.Context) {
		if created || previous.Backbone == nil {
			_ = a.runner.Run(rollbackCtx, nil, "ip", "rule", "del", "priority", "100")
			_ = a.runner.Run(rollbackCtx, nil, "ip", "link", "del", "dev", b.InterfaceName)
			return
		}
		_, _ = a.applyWireGuard(rollbackCtx, previous, state)
	}
	if previous.Backbone != nil && previous.Backbone.InterfaceName == b.InterfaceName {
		old := previous.Backbone
		if old.TunnelAddress != b.TunnelAddress {
			// address replace is additive when the prefix changes. Remove the
			// previously owned address so source-address selection cannot keep
			// routing traffic toward a retired exit.
			_ = a.runner.Run(ctx, nil, "ip", "address", "del", old.TunnelAddress.String(), "dev", b.InterfaceName)
		}
		if old.PeerPublicKey != b.PeerPublicKey {
			// wg set is also additive for peers. A migrated backbone must have
			// exactly one controller-owned peer.
			_ = a.runner.Run(ctx, nil, "wg", "set", b.InterfaceName, "peer", old.PeerPublicKey, "remove")
		}
	}
	allowedIPs := "0.0.0.0/0"
	if state.Role == RoleExit {
		allowedIPs = netip.PrefixFrom(b.PeerTunnelAddress, 32).String()
	}
	commands := [][]string{
		{"ip", "address", "replace", b.TunnelAddress.String(), "dev", b.InterfaceName},
		{"wg", "set", b.InterfaceName, "private-key", keyPath, "listen-port", strconv.Itoa(b.ListenPort), "peer", b.PeerPublicKey, "endpoint", b.PeerEndpoint.String(), "allowed-ips", allowedIPs, "persistent-keepalive", "25"},
		{"ip", "link", "set", "up", "dev", b.InterfaceName},
	}
	if state.Role == RoleIngress {
		// `ip rule replace` is not supported consistently across iproute2
		// versions. Delete only our fixed priority and add the exact rule back.
		_ = a.runner.Run(ctx, nil, "ip", "rule", "del", "priority", "100")
		commands = append(commands,
			[]string{"ip", "route", "replace", "default", "dev", b.InterfaceName, "table", policyTable},
			[]string{"ip", "rule", "add", "priority", "100", "uidrange", fmt.Sprintf("%d-%d", b.IngressUID, b.IngressUID), "lookup", policyTable})
	}
	for _, command := range commands {
		if err := a.runner.Run(ctx, nil, command[0], command[1:]...); err != nil {
			rollback(ctx)
			return nil, err
		}
	}
	if state.Role == RoleExit {
		if err := a.requireIPv4Forwarding(); err != nil {
			rollback(ctx)
			return nil, err
		}
	}
	return rollback, nil
}

func (a *Applier) requireIPv4Forwarding() error {
	value, err := os.ReadFile(a.ipForwardPath)
	if err != nil {
		return fmt.Errorf("read net.ipv4.ip_forward: %w", err)
	}
	if strings.TrimSpace(string(value)) != "1" {
		return errors.New("net.ipv4.ip_forward must be enabled on the exit host")
	}
	return nil
}

const dockerForwardComment = "guardex-transport"

func dockerForwardRules(state DesiredState) [][]string {
	if !state.Enabled {
		return nil
	}
	switch state.Role {
	case RoleExit:
		b := state.Backbone
		return [][]string{
			{"-i", b.InterfaceName, "-o", b.EgressInterface, "-m", "comment", "--comment", dockerForwardComment, "-j", "ACCEPT"},
			{"-i", b.EgressInterface, "-o", b.InterfaceName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", dockerForwardComment, "-j", "ACCEPT"},
		}
	case RoleRelay:
		r := state.Relay
		rules := make([][]string, 0, 3)
		if r.TCPEnabled {
			rules = append(rules, []string{"-d", r.IngressAddress.String(), "-p", "tcp", "--dport", "443", "-m", "comment", "--comment", dockerForwardComment, "-j", "ACCEPT"})
		}
		if r.UDPEnabled {
			rules = append(rules, []string{"-d", r.IngressAddress.String(), "-p", "udp", "--dport", "443", "-m", "comment", "--comment", dockerForwardComment, "-j", "ACCEPT"})
		}
		return append(rules, []string{"-s", r.IngressAddress.String(), "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", dockerForwardComment, "-j", "ACCEPT"})
	default:
		return nil
	}
}

func (a *Applier) ensureDockerForwarding(ctx context.Context, state DesiredState) (func(context.Context), error) {
	rules := dockerForwardRules(state)
	if len(rules) == 0 {
		return func(context.Context) {}, nil
	}
	if err := a.runner.Run(ctx, nil, "iptables", "-w", "-t", "filter", "-S", "DOCKER-USER"); err != nil {
		return nil, errors.New("Docker DOCKER-USER forwarding chain is unavailable")
	}
	added := make([][]string, 0, len(rules))
	for _, rule := range rules {
		check := append([]string{"-w", "-t", "filter", "-C", "DOCKER-USER"}, rule...)
		if a.runner.Run(ctx, nil, "iptables", check...) == nil {
			continue
		}
		insert := append([]string{"-w", "-t", "filter", "-I", "DOCKER-USER", "1"}, rule...)
		if err := a.runner.Run(ctx, nil, "iptables", insert...); err != nil {
			a.removeDockerForwarding(ctx, added)
			return nil, err
		}
		added = append(added, rule)
	}
	return func(rollbackCtx context.Context) { a.removeDockerForwarding(rollbackCtx, added) }, nil
}

func (a *Applier) removeDockerForwarding(ctx context.Context, rules [][]string) {
	for _, rule := range rules {
		remove := append([]string{"-w", "-t", "filter", "-D", "DOCKER-USER"}, rule...)
		_ = a.runner.Run(ctx, nil, "iptables", remove...)
	}
}

func (a *Applier) removeOwned(ctx context.Context, current DesiredState) error {
	a.removeDockerForwarding(ctx, dockerForwardRules(current))
	if a.runner.Run(ctx, nil, "nft", "list", "table", "inet", TableName) == nil {
		if err := a.runner.Run(ctx, []byte("delete table inet "+TableName+"\n"), "nft", "-f", "-"); err != nil {
			return err
		}
	}
	if current.Backbone != nil {
		if current.Role == RoleIngress {
			_ = a.runner.Run(ctx, nil, "ip", "rule", "del", "priority", "100")
		}
		_ = a.runner.Run(ctx, nil, "ip", "link", "del", "dev", current.Backbone.InterfaceName)
	}
	return nil
}

func missingForwardRules(previous, next [][]string) [][]string {
	keep := make(map[string]struct{}, len(next))
	for _, rule := range next {
		keep[strings.Join(rule, "\x00")] = struct{}{}
	}
	missing := make([][]string, 0, len(previous))
	for _, rule := range previous {
		if _, ok := keep[strings.Join(rule, "\x00")]; !ok {
			missing = append(missing, rule)
		}
	}
	return missing
}

func (a *Applier) ensurePrivateKey() ([]byte, error) {
	if err := os.MkdirAll(a.root, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(a.root, "wireguard.raw")
	if value, err := os.ReadFile(path); err == nil && len(value) == curve25519.ScalarSize {
		return value, nil
	}
	value := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	value[0] &= 248
	value[31] &= 127
	value[31] |= 64
	tmp, err := os.CreateTemp(a.root, ".wg-key-")
	if err != nil {
		return nil, err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(value); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(name, path); err != nil {
		return nil, err
	}
	return value, nil
}

func (a *Applier) loadState() (DesiredState, error) {
	var state DesiredState
	raw, err := os.ReadFile(filepath.Join(a.root, "state.json"))
	if err != nil {
		return state, err
	}
	err = json.Unmarshal(raw, &state)
	return state, err
}
func (a *Applier) saveState(state DesiredState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(a.root, ".state-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(raw)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(a.root, "state.json"))
}
