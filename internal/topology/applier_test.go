package topology

import (
	"context"
	"errors"
	"net/netip"
	"os"
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
	state := DesiredState{SchemaVersion: 1, Revision: 2, Role: RoleRelay, Enabled: true, Relay: &Relay{IngressAddress: netip.MustParseAddr("203.0.113.10"), IngressPort: 443, TCPEnabled: true, UDPEnabled: true}}
	if err := applier.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	var check, apply bool
	for _, command := range runner.commands {
		if command.name == "nft" && strings.Contains(command.stdin, "dnat to 203.0.113.10:443") {
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
	first := DesiredState{SchemaVersion: 1, Revision: 3, Role: RoleRelay, Enabled: true, Relay: &Relay{IngressAddress: netip.MustParseAddr("203.0.113.10"), IngressPort: 443, TCPEnabled: true}}
	if err := applier.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	first.Relay.IngressAddress = netip.MustParseAddr("203.0.113.11")
	if err := applier.Apply(context.Background(), first); !errors.Is(err, ErrUnsafeDesiredState) {
		t.Fatalf("same revision mutation accepted: %v", err)
	}
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
