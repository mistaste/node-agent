package topology

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type recordedCommand struct {
	name  string
	args  []string
	stdin string
}
type recordingRunner struct{ commands []recordedCommand }

func (r *recordingRunner) Run(_ context.Context, stdin []byte, name string, args ...string) error {
	r.commands = append(r.commands, recordedCommand{name: name, args: append([]string(nil), args...), stdin: string(stdin)})
	if name == "nft" && len(args) > 0 && args[0] == "list" {
		return errors.New("not found")
	}
	if name == "ip" && len(args) > 1 && args[0] == "link" && args[1] == "show" {
		return errors.New("not found")
	}
	return nil
}

type failingRunner struct {
	recordingRunner
	failNFTCheck bool
}

type missingDockerRuleRunner struct{ recordingRunner }

type restartRunner struct {
	recordingRunner
	interfacePresent bool
}

func (r *restartRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) error {
	r.commands = append(r.commands, recordedCommand{name: name, args: append([]string(nil), args...), stdin: string(stdin)})
	joined := strings.Join(args, " ")
	if name == "ip" && joined == "link show dev gxwg0" && !r.interfacePresent {
		return errors.New("not found")
	}
	if name == "ip" && joined == "link set dev gxwg0 mtu 1280" && !r.interfacePresent {
		return errors.New("not found")
	}
	if name == "ip" && joined == "link add dev gxwg0 type wireguard" {
		r.interfacePresent = true
	}
	if name == "nft" && len(args) > 0 && args[0] == "list" {
		return errors.New("not found")
	}
	return nil
}

func (r *missingDockerRuleRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) error {
	err := r.recordingRunner.Run(ctx, stdin, name, args...)
	if name == "iptables" && len(args) > 3 && args[3] == "-C" {
		return errors.New("rule not found")
	}
	return err
}

func (r *failingRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) error {
	if r.failNFTCheck && name == "nft" && len(args) > 0 && args[0] == "-c" {
		r.commands = append(r.commands, recordedCommand{name: name, args: append([]string(nil), args...), stdin: string(stdin)})
		return errors.New("invalid transaction")
	}
	return r.recordingRunner.Run(ctx, stdin, name, args...)
}

func TestApplierValidatesThenAtomicallyChecksAndAppliesRelay(t *testing.T) {
	runner := &recordingRunner{}
	applier, _ := NewApplier(t.TempDir())
	applier.runner = runner
	state := DesiredState{SchemaVersion: 1, Revision: 2, Role: RoleRelay, Enabled: true, Relay: &Relay{IngressAddress: netip.MustParseAddr("93.184.216.34"), IngressPort: 443, TCPEnabled: true, UDPEnabled: true}}
	if err := applier.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	var check, apply bool
	for _, command := range runner.commands {
		if command.name == "nft" && strings.Contains(command.stdin, "dnat ip to 93.184.216.34:443") {
			if len(command.args) > 0 && command.args[0] == "-c" {
				check = true
			} else {
				apply = true
			}
		}
	}
	if !check || !apply {
		t.Fatalf("missing nft validation/apply: %#v", runner.commands)
	}
}

func TestApplierRejectsSameRevisionMutation(t *testing.T) {
	runner := &recordingRunner{}
	applier, _ := NewApplier(t.TempDir())
	applier.runner = runner
	first := DesiredState{SchemaVersion: 1, Revision: 3, Role: RoleRelay, Enabled: true, Relay: &Relay{IngressAddress: netip.MustParseAddr("93.184.216.34"), IngressPort: 443, TCPEnabled: true}}
	if err := applier.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	first.Relay.IngressAddress = netip.MustParseAddr("93.184.216.35")
	if err := applier.Apply(context.Background(), first); !errors.Is(err, ErrUnsafeDesiredState) {
		t.Fatalf("same revision mutation accepted: %v", err)
	}
}

func TestApplierAllowsSameRevisionExitProbeRefresh(t *testing.T) {
	runner := &recordingRunner{}
	applier, _ := NewApplier(t.TempDir())
	applier.runner = runner
	state := backboneState(RoleIngress)
	if err := applier.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	state.ExitProbes = []ExitProbe{{
		ExitServerID: "61f4d9d0-c0d3-4de2-8685-e4732823f2ab",
		Endpoint:     netip.MustParseAddrPort("82.47.46.112:8099"),
	}}
	if err := applier.Apply(context.Background(), state); err != nil {
		t.Fatalf("operational exit-probe refresh rejected: %v", err)
	}
	last := runner.commands[len(runner.commands)-1]
	if last.name != "ip" || strings.Join(last.args, " ") != "link set dev gxwg0 mtu 1280" {
		t.Fatalf("same-revision runtime MTU was not reconciled: %#v", last)
	}
}

func TestApplierRebuildsMissingBackboneAtSameRevision(t *testing.T) {
	runner := &restartRunner{}
	applier, _ := NewApplier(t.TempDir())
	applier.runner = runner
	state := backboneState(RoleIngress)
	if err := applier.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	runner.interfacePresent = false
	runner.commands = nil
	if err := applier.Apply(context.Background(), state); err != nil {
		t.Fatalf("same-revision runtime recovery failed: %v", err)
	}
	for _, command := range runner.commands {
		if command.name == "ip" && strings.Join(command.args, " ") == "link add dev gxwg0 type wireguard" {
			return
		}
	}
	t.Fatalf("missing WireGuard interface was not rebuilt: %#v", runner.commands)
}

func TestBackboneConfigNeverPlacesPrivateKeyOnCommandLine(t *testing.T) {
	runner := &recordingRunner{}
	applier, _ := NewApplier(t.TempDir())
	applier.runner = runner
	state := backboneState(RoleIngress)
	if err := applier.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	for _, command := range runner.commands {
		joined := strings.Join(append([]string{command.name}, command.args...), " ")
		if strings.Contains(joined, "wireguard.raw") {
			t.Fatalf("raw private key path exposed to command: %s", joined)
		}
		if strings.Contains(command.stdin, "private") {
			t.Fatalf("private material sent to nft")
		}
	}
}

func TestExitPeerIsLimitedToIngressTunnelAddress(t *testing.T) {
	runner := &recordingRunner{}
	applier, _ := NewApplier(t.TempDir())
	applier.runner = runner
	applier.ipForwardPath = enabledIPv4Forwarding(t)
	if err := applier.Apply(context.Background(), backboneState(RoleExit)); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if command.name == "wg" && strings.Contains(joined, "allowed-ips 10.91.0.2/32") {
			found = true
		}
		if command.name == "wg" && strings.Contains(joined, "allowed-ips 0.0.0.0/0") {
			t.Fatalf("exit accepted an unrestricted ingress peer: %s", joined)
		}
	}
	if !found {
		t.Fatalf("exit peer tunnel restriction missing: %#v", runner.commands)
	}
}

func TestWireGuardUsesCrossProviderSafeMTU(t *testing.T) {
	runner := &recordingRunner{}
	applier, _ := NewApplier(t.TempDir())
	applier.runner = runner
	if err := applier.Apply(context.Background(), backboneState(RoleIngress)); err != nil {
		t.Fatal(err)
	}
	for _, command := range runner.commands {
		if command.name == "ip" && strings.Join(command.args, " ") == "link set dev gxwg0 mtu 1280" {
			return
		}
	}
	t.Fatalf("safe WireGuard MTU command missing: %#v", runner.commands)
}

func TestBackboneMigrationRemovesRetiredAddressAndPeer(t *testing.T) {
	runner := &recordingRunner{}
	applier, _ := NewApplier(t.TempDir())
	applier.runner = runner
	first := backboneState(RoleIngress)
	if err := applier.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	second := backboneState(RoleIngress)
	second.Revision = first.Revision + 1
	second.Backbone.TunnelAddress = netip.MustParsePrefix("10.92.0.1/30")
	second.Backbone.PeerTunnelAddress = netip.MustParseAddr("10.92.0.2")
	second.Backbone.PeerPublicKey = "X6iCcvOewJyIITUO42yCLKvKHTNBolQObM+7U/NU7zk="
	runner.commands = nil
	if err := applier.Apply(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	removedAddress := false
	removedPeer := false
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		removedAddress = removedAddress || command.name == "ip" && joined == "address del 10.91.0.1/30 dev gxwg0"
		removedPeer = removedPeer || command.name == "wg" && strings.Contains(joined, "peer "+first.Backbone.PeerPublicKey+" remove")
	}
	if !removedAddress || !removedPeer {
		t.Fatalf("migration retained stale WireGuard state: %#v", runner.commands)
	}
}

func TestIngressInstallsOuterWireGuardRoutingException(t *testing.T) {
	runner := &recordingRunner{}
	applier, _ := NewApplier(t.TempDir())
	applier.runner = runner
	if err := applier.Apply(context.Background(), backboneState(RoleIngress)); err != nil {
		t.Fatal(err)
	}
	foundEndpoint := false
	foundReply := false
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		foundEndpoint = foundEndpoint || command.name == "ip" && joined == "rule add priority 90 to 93.184.216.34/32 lookup main"
		foundReply = foundReply || command.name == "ip" && joined == "rule add priority 80 fwmark 0x4758 lookup main"
	}
	if !foundEndpoint || !foundReply {
		t.Fatalf("ingress route exceptions missing: %#v", runner.commands)
	}
}

func TestExitInstallsAndRemovesOwnedDockerForwardingRules(t *testing.T) {
	runner := &missingDockerRuleRunner{}
	applier, _ := NewApplier(t.TempDir())
	applier.runner = runner
	applier.ipForwardPath = enabledIPv4Forwarding(t)
	if err := applier.Apply(context.Background(), backboneState(RoleExit)); err != nil {
		t.Fatal(err)
	}
	inserts := 0
	for _, command := range runner.commands {
		if command.name == "iptables" && strings.Contains(strings.Join(command.args, " "), "-I DOCKER-USER 1") {
			inserts++
		}
	}
	if inserts != 2 {
		t.Fatalf("installed %d Docker forwarding rules, want 2: %#v", inserts, runner.commands)
	}
	if err := applier.RemoveUnassigned(context.Background()); err != nil {
		t.Fatal(err)
	}
	removes := 0
	for _, command := range runner.commands {
		if command.name == "iptables" && strings.Contains(strings.Join(command.args, " "), "-D DOCKER-USER") {
			removes++
		}
	}
	if removes != 2 {
		t.Fatalf("removed %d Docker forwarding rules, want 2: %#v", removes, runner.commands)
	}
}

func TestRelayDockerRulesRemainRestrictedToFixedIngress(t *testing.T) {
	state := DesiredState{SchemaVersion: 1, Revision: 2, Role: RoleRelay, Enabled: true, Relay: &Relay{IngressAddress: netip.MustParseAddr("93.184.216.34"), IngressPort: 443, TCPEnabled: true, UDPEnabled: true}}
	rules := dockerForwardRules(state)
	if len(rules) != 3 {
		t.Fatalf("relay Docker rules=%d want=3", len(rules))
	}
	for _, rule := range rules[:2] {
		joined := strings.Join(rule, " ")
		if !strings.Contains(joined, "-d 93.184.216.34") || !strings.Contains(joined, "--dport 443") {
			t.Fatalf("relay rule permits a non-fixed target: %s", joined)
		}
	}
}

func TestBackboneIsRemovedWhenFirewallTransactionFails(t *testing.T) {
	runner := &failingRunner{failNFTCheck: true}
	applier, _ := NewApplier(t.TempDir())
	applier.runner = runner
	if err := applier.Apply(context.Background(), backboneState(RoleIngress)); err == nil {
		t.Fatal("expected nft validation failure")
	}
	removed := false
	for _, command := range runner.commands {
		if command.name == "ip" && strings.Join(command.args, " ") == "link del dev gxwg0" {
			removed = true
		}
	}
	if !removed {
		t.Fatalf("partially applied backbone was not rolled back: %#v", runner.commands)
	}
	if _, err := applier.loadState(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed revision was persisted: %v", err)
	}
}

func TestUnassignedNodeRemovesNewerLiveTopology(t *testing.T) {
	runner := &recordingRunner{}
	applier, _ := NewApplier(t.TempDir())
	applier.runner = runner
	state := backboneState(RoleIngress)
	state.Revision = 9
	if err := applier.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	runner.commands = nil

	if err := applier.RemoveUnassigned(context.Background()); err != nil {
		t.Fatal(err)
	}
	removedLink := false
	removedRule := false
	for _, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		removedLink = removedLink || command.name == "ip" && joined == "link del dev gxwg0"
		removedRule = removedRule || command.name == "ip" && joined == "rule del priority 100"
	}
	if !removedLink || !removedRule {
		t.Fatalf("unassigned cleanup left owned networking active: %#v", runner.commands)
	}
	stored, err := applier.loadState()
	if err != nil {
		t.Fatal(err)
	}
	if stored.Enabled || stored.Role != "" || stored.Revision != 10 {
		t.Fatalf("unexpected unassigned tombstone: %+v", stored)
	}
}

func TestUnassignedTombstoneIsIdempotentAndAllowsFreshAssignment(t *testing.T) {
	runner := &recordingRunner{}
	applier, _ := NewApplier(t.TempDir())
	applier.runner = runner
	state := backboneState(RoleIngress)
	state.Revision = 7
	if err := applier.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if err := applier.RemoveUnassigned(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := applier.loadState()
	if err != nil {
		t.Fatal(err)
	}
	if err := applier.RemoveUnassigned(context.Background()); err != nil {
		t.Fatal(err)
	}
	repeated, err := applier.loadState()
	if err != nil {
		t.Fatal(err)
	}
	if repeated.Revision != first.Revision {
		t.Fatalf("unassigned tombstone advanced repeatedly: %d -> %d", first.Revision, repeated.Revision)
	}

	fresh := DesiredState{
		SchemaVersion: 1,
		Revision:      1,
		Role:          RoleRelay,
		Enabled:       true,
		Relay: &Relay{
			IngressAddress: netip.MustParseAddr("93.184.216.34"),
			IngressPort:    443,
			TCPEnabled:     true,
		},
	}
	if err := applier.Apply(context.Background(), fresh); err != nil {
		t.Fatalf("fresh assignment was blocked by local tombstone: %v", err)
	}
}

func TestRoleTransitionRemovesPreviousBackboneBeforeRelay(t *testing.T) {
	runner := &recordingRunner{}
	applier, _ := NewApplier(t.TempDir())
	applier.runner = runner
	if err := applier.Apply(context.Background(), backboneState(RoleIngress)); err != nil {
		t.Fatal(err)
	}
	runner.commands = nil
	relay := DesiredState{
		SchemaVersion: 1,
		Revision:      2,
		Role:          RoleRelay,
		Enabled:       true,
		Relay: &Relay{
			IngressAddress: netip.MustParseAddr("93.184.216.34"),
			IngressPort:    443,
			TCPEnabled:     true,
		},
	}
	if err := applier.Apply(context.Background(), relay); err != nil {
		t.Fatal(err)
	}
	removedAt := -1
	appliedAt := -1
	for index, command := range runner.commands {
		joined := strings.Join(command.args, " ")
		if command.name == "ip" && joined == "link del dev gxwg0" {
			removedAt = index
		}
		if command.name == "nft" && strings.Contains(command.stdin, "dnat ip to 93.184.216.34:443") && len(command.args) > 0 && command.args[0] == "-c" {
			appliedAt = index
		}
	}
	if removedAt < 0 || appliedAt < 0 || removedAt >= appliedAt {
		t.Fatalf("old backbone was not removed before relay validation: %#v", runner.commands)
	}
}

func TestExitResolvesPublicInterfaceFromLocalDefaultRoute(t *testing.T) {
	runner := &recordingRunner{}
	applier, _ := NewApplier(t.TempDir())
	applier.runner = runner
	applier.ipForwardPath = enabledIPv4Forwarding(t)
	applier.routeTablePath = filepath.Join(t.TempDir(), "route")
	routes := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n" +
		"ens3\t00000000\t010010AC\t0003\t0\t0\t100\t00000000\n"
	if err := os.WriteFile(applier.routeTablePath, []byte(routes), 0600); err != nil {
		t.Fatal(err)
	}
	state := backboneState(RoleExit)
	state.Backbone.EgressInterface = "auto"
	if err := applier.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, command := range runner.commands {
		if command.name == "nft" && strings.Contains(command.stdin, `oifname "ens3" masquerade`) {
			found = true
		}
		if strings.Contains(command.stdin, `oifname "auto"`) {
			t.Fatalf("unresolved exit interface reached nftables: %s", command.stdin)
		}
	}
	if !found {
		t.Fatalf("local default exit interface was not used: %#v", runner.commands)
	}
}

func TestExitFailsClosedWhenHostForwardingIsDisabled(t *testing.T) {
	runner := &recordingRunner{}
	applier, _ := NewApplier(t.TempDir())
	applier.runner = runner
	applier.ipForwardPath = filepath.Join(t.TempDir(), "ip_forward")
	if err := os.WriteFile(applier.ipForwardPath, []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := applier.Apply(context.Background(), backboneState(RoleExit)); err == nil ||
		!strings.Contains(err.Error(), "must be enabled on the exit host") {
		t.Fatalf("disabled forwarding was accepted: %v", err)
	}
	if _, err := applier.loadState(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed exit revision was persisted: %v", err)
	}
}

func enabledIPv4Forwarding(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ip_forward")
	if err := os.WriteFile(path, []byte("1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
