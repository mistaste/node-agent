package topology

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func udpPolicyHarness(t *testing.T, port int, rules string) (*Applier, *policyRunner, string) {
	t.Helper()
	root := t.TempDir()
	statePath := filepath.Join(root, "runner-state.json")
	if port != 0 {
		// Actual deployed runner ACK schema: deliberately no port field.
		raw := fmt.Sprintf(`{"version":1,"inbound_id":"fixture","revision":7,"digest":%q,"client_set_sha256":%q,"h3_port":443}`, strings.Repeat("a", 64), strings.Repeat("b", 64))
		if err := os.WriteFile(statePath, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		raw = strings.TrimSuffix(raw, "}") + fmt.Sprintf(`,"port":%d,"tag":"fixture","client_count":3}`, port)
		if err := os.WriteFile(filepath.Join(root, "state.json"), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
	a, _ := NewApplier(filepath.Join(root, "topology"))
	if err := os.Mkdir(a.root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := a.SetTrustTunnelStatePath(statePath); err != nil {
		t.Fatal(err)
	}
	runner := &policyRunner{rules: rules}
	a.runner = runner
	return a, runner, statePath
}

func TestIngressUDPSourcePolicyKeepsLKGUntilDesiredStateIsAcknowledged(t *testing.T) {
	for _, change := range []struct{ old, new string }{
		{`"inbound_id":"fixture"`, `"inbound_id":"other"`},
		{`"revision":7`, `"revision":8`},
		{strings.Repeat("a", 64), strings.Repeat("c", 64)},
		{strings.Repeat("b", 64), strings.Repeat("c", 64)},
	} {
		a, runner, path := udpPolicyHarness(t, 8443, "["+udpOwnedRule(18443)+"]")
		desiredPath := filepath.Join(filepath.Dir(path), "state.json")
		raw, _ := os.ReadFile(desiredPath)
		if err := os.WriteFile(desiredPath, []byte(strings.Replace(string(raw), change.old, change.new, 1)), 0600); err != nil {
			t.Fatal(err)
		}
		if err := a.ensureIngressUDPSourcePolicy(context.Background(), backboneState(RoleIngress)); err != nil {
			t.Fatal(err)
		}
		if len(runner.commands) != 0 {
			t.Fatal("unacknowledged state changed the active source route")
		}
	}
	a, runner, path := udpPolicyHarness(t, 8443, "["+udpOwnedRule(18443)+"]")
	if err := os.Remove(filepath.Join(filepath.Dir(path), "state.json")); err != nil {
		t.Fatal(err)
	}
	if err := a.ensureIngressUDPSourcePolicy(context.Background(), backboneState(RoleIngress)); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 0 {
		t.Fatal("missing desired metadata changed the active source route")
	}
}

func udpOwnedRule(port int) string {
	return fmt.Sprintf(`{"priority":95,"src":"all","uid_start":65532,"uid_end":65532,"ipproto":"udp","sport":%d,"table":"main","protocol":"242"}`, port)
}

func TestIngressUDPSourcePolicyUsesAcknowledgedPortAndKeepsHealthyRule(t *testing.T) {
	for _, port := range []int{443, 8443, 18443} {
		t.Run(fmt.Sprint(port), func(t *testing.T) {
			a, runner, _ := udpPolicyHarness(t, port, `[]`)
			if err := a.ensureIngressUDPSourcePolicy(context.Background(), backboneState(RoleIngress)); err != nil {
				t.Fatal(err)
			}
			if len(runner.commands) != 1 || runner.commands[0].name != "ip" ||
				strings.Join(runner.commands[0].args, " ") != strings.Join(ingressUDPSourceArgs("add", 65532, port), " ") {
				t.Fatalf("unexpected runtime mutations: %+v", runner.commands)
			}
			runner.commands = nil
			runner.rules = "[" + udpOwnedRule(port) + "]"
			if err := a.ensureIngressUDPSourcePolicy(context.Background(), backboneState(RoleIngress)); err != nil {
				t.Fatal(err)
			}
			if len(runner.commands) != 0 {
				t.Fatal("healthy source rule was rewritten")
			}
		})
	}
}

func TestIngressUDPSourcePortChangeIsAddBeforeExactDelete(t *testing.T) {
	a, runner, _ := udpPolicyHarness(t, 18443, "["+udpOwnedRule(8443)+"]")
	if err := a.ensureIngressUDPSourcePolicy(context.Background(), backboneState(RoleIngress)); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("unexpected port replacement: %+v", runner.commands)
	}
	for i, expected := range [][]string{ingressUDPSourceArgs("add", 65532, 18443), ingressUDPSourceArgs("del", 65532, 8443)} {
		if runner.commands[i].name != "ip" || strings.Join(runner.commands[i].args, " ") != strings.Join(expected, " ") {
			t.Fatalf("unsafe source-rule replacement: %+v", runner.commands)
		}
	}
}

func TestIngressUDPSourcePolicyRejectsOtherOwnerWithoutMutation(t *testing.T) {
	for _, rule := range []string{
		strings.Replace(udpOwnedRule(8443), `"242"`, `"static"`, 1),
		strings.Replace(udpOwnedRule(8443), `"udp"`, `"tcp"`, 1),
		strings.Replace(udpOwnedRule(8443), `"main"`, `"51820"`, 1),
		strings.Replace(udpOwnedRule(8443), `"uid_start":65532`, `"uid_start":1`, 1),
		strings.Replace(udpOwnedRule(8443), `"src":"all"`, `"src":"all","fwmark":"0x1"`, 1),
	} {
		a, runner, _ := udpPolicyHarness(t, 18443, "["+rule+"]")
		if err := a.ensureIngressUDPSourcePolicy(context.Background(), backboneState(RoleIngress)); err == nil {
			t.Fatal("conflicting source policy accepted")
		}
		if len(runner.commands) != 0 {
			t.Fatal("changed runtime while source-policy ownership was uncertain")
		}
	}
}

func TestIngressUDPSourcePolicyKeepsLKGWhileRunnerAcknowledgementMissing(t *testing.T) {
	a, runner, path := udpPolicyHarness(t, 0, "["+udpOwnedRule(18443)+"]")
	if err := a.ensureIngressUDPSourcePolicy(context.Background(), backboneState(RoleIngress)); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 0 {
		t.Fatal("missing transient acknowledgement removed a healthy source route")
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"port":-1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.ensureIngressUDPSourcePolicy(context.Background(), backboneState(RoleIngress)); err == nil {
		t.Fatal("invalid runner port accepted")
	}
	if len(runner.commands) != 0 {
		t.Fatal("invalid runner metadata changed the network")
	}
}

func TestIngressUDPSourcePolicyRemovalIsExactlyOwned(t *testing.T) {
	a, runner, _ := udpPolicyHarness(t, 18443, "["+udpOwnedRule(18443)+"]")
	if err := a.removeIngressUDPSourcePolicy(context.Background(), 65532); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 || strings.Join(runner.commands[0].args, " ") != strings.Join(ingressUDPSourceArgs("del", 65532, 18443), " ") {
		t.Fatalf("unsafe teardown: %+v", runner.commands)
	}
}

type udpTransactionRunner struct {
	policyRunner
	oldNFT           string
	interfacePresent bool
	failCommand      string
	failed           bool
	onSourceAdd      func()
}

func (r *udpTransactionRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "nft" {
		return []byte(r.oldNFT), nil
	}
	return r.policyRunner.Output(ctx, name, args...)
}

func (r *udpTransactionRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) error {
	r.commands = append(r.commands, recordedCommand{name, append([]string(nil), args...), string(stdin)})
	command := name + " " + strings.Join(args, " ")
	if command == r.failCommand && !r.failed {
		r.failed = true
		return errors.New("injected command failure")
	}
	if name == "nft" && len(args) > 0 && args[0] == "list" && r.oldNFT == "" {
		return errors.New("not found")
	}
	if command == "ip link show dev gxwg0" && !r.interfacePresent {
		return errors.New("not found")
	}
	if strings.HasPrefix(command, "ip rule add priority 95 ") && r.onSourceAdd != nil {
		r.onSourceAdd()
	}
	return nil
}

func TestIngressUDPSourceReplacementFailureRestoresExactPreviousRules(t *testing.T) {
	a, _, _ := udpPolicyHarness(t, 18443, "[]")
	r := &udpTransactionRunner{policyRunner: policyRunner{rules: "[" + udpOwnedRule(8443) + "]"}, failCommand: "ip " + strings.Join(ingressUDPSourceArgs("del", 65532, 8443), " ")}
	a.runner = r
	if err := a.ensureIngressUDPSourcePolicy(context.Background(), backboneState(RoleIngress)); err == nil {
		t.Fatal("expected injected failure")
	}
	want := [][]string{ingressUDPSourceArgs("add", 65532, 18443), ingressUDPSourceArgs("del", 65532, 8443), ingressUDPSourceArgs("del", 65532, 18443)}
	if len(r.commands) != len(want) {
		t.Fatalf("unexpected rollback: %+v", r.commands)
	}
	for i, args := range want {
		if strings.Join(r.commands[i].args, " ") != strings.Join(args, " ") {
			t.Fatalf("unsafe rollback: %+v", r.commands)
		}
	}
}

func TestIngressUDPSourceUIDChangeReplacesOldOwnedUID(t *testing.T) {
	a, r, _ := udpPolicyHarness(t, 18443, "["+udpOwnedRule(18443)+"]")
	s := backboneState(RoleIngress)
	s.Backbone.IngressUID = 65531
	p, err := a.prepareIngressUDPSourcePolicy(context.Background(), s, 65532)
	if err != nil {
		t.Fatal(err)
	}
	undo, err := p.apply(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := undo(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := [][]string{ingressUDPSourceArgs("add", 65531, 18443), ingressUDPSourceArgs("del", 65532, 18443), ingressUDPSourceArgs("add", 65532, 18443), ingressUDPSourceArgs("del", 65531, 18443)}
	if len(r.commands) != len(want) {
		t.Fatalf("unexpected UID journal: %+v", r.commands)
	}
	for i, args := range want {
		if strings.Join(r.commands[i].args, " ") != strings.Join(args, " ") {
			t.Fatalf("unsafe UID journal: %+v", r.commands)
		}
	}
}

func TestIngressUDPConflictPreflightDoesNotTouchWorkingTopology(t *testing.T) {
	a, r, _ := udpPolicyHarness(t, 18443, "["+strings.Replace(udpOwnedRule(8443), `"242"`, `"static"`, 1)+"]")
	s := backboneState(RoleIngress)
	if err := a.saveState(s); err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(context.Background(), s); err == nil {
		t.Fatal("expected ownership conflict")
	}
	if len(r.commands) != 0 {
		t.Fatalf("preflight mutated working topology: %+v", r.commands)
	}
}

func TestIngressUDPApplyFailureRestoresGuardAndSurvivingBackbone(t *testing.T) {
	for _, failure := range []string{"source_add", "save_state", "fresh_source_add"} {
		t.Run(failure, func(t *testing.T) {
			a, _, _ := udpPolicyHarness(t, 18443, "[]")
			s := backboneState(RoleIngress)
			r := &udpTransactionRunner{policyRunner: policyRunner{rules: "[]"}}
			a.runner = r
			if failure != "fresh_source_add" {
				r.oldNFT = "table inet guardex_transport { chain output { type filter hook output priority -5; policy accept; meta skuid 65532 reject; } }\n"
				r.interfacePresent = true
				if err := a.saveState(s); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "save_state" {
				r.onSourceAdd = func() {
					if err := os.Rename(filepath.Join(a.root, "state.json"), filepath.Join(a.root, "state.before")); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(filepath.Join(a.root, "state.json"), 0700); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				r.failCommand = "ip " + strings.Join(ingressUDPSourceArgs("add", 65532, 18443), " ")
			}
			if err := a.Apply(context.Background(), s); err == nil {
				t.Fatal("expected injected apply failure")
			}
			var lastNFT string
			var sourceWithdrawn bool
			for _, c := range r.commands {
				if c.name == "nft" && strings.Join(c.args, " ") == "-f -" {
					lastNFT = c.stdin
				}
				if c.name == "ip" && strings.Join(c.args, " ") == strings.Join(ingressUDPSourceArgs("del", 65532, 18443), " ") {
					sourceWithdrawn = true
				}
				if failure != "fresh_source_add" && c.name == "ip" && strings.Join(c.args, " ") == "link del dev gxwg0" {
					t.Fatal("deleted surviving backbone during rollback")
				}
			}
			if failure == "fresh_source_add" {
				if !strings.Contains(lastNFT, "meta skuid 65532 reject") || strings.Contains(lastNFT, "ct direction reply") {
					t.Fatalf("fresh failure did not leave reject-only guard: %s", lastNFT)
				}
			} else if lastNFT != "delete table inet guardex_transport\n"+r.oldNFT {
				t.Fatalf("previous guard was not restored: %s", lastNFT)
			}
			if failure == "save_state" && !sourceWithdrawn {
				t.Fatal("later failure retained new source route")
			}
		})
	}
}
