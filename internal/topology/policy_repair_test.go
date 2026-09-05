package topology

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

type policyRunner struct {
	recordingRunner
	rules string
}

func (r *policyRunner) Output(context.Context, string, ...string) ([]byte, error) {
	return []byte(r.rules), nil
}

func TestSameRevisionRepairsMissingPolicyWithoutTunnelRestart(t *testing.T) {
	r := &policyRunner{rules: `[]`}
	a, _ := NewApplier(t.TempDir())
	a.runner = r
	s := backboneState(RoleIngress)
	if err := a.Apply(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	r.commands = nil
	if err := a.Apply(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	adds := 0
	for _, command := range r.commands {
		args := strings.Join(command.args, " ")
		if strings.HasPrefix(args, "rule add") {
			adds++
		}
		if command.name == "wg" || command.name == "nft" || strings.Contains(args, "rule del") || strings.Contains(args, "link del") {
			t.Fatalf("disruptive repair: %v", command)
		}
	}
	if adds != 3 {
		t.Fatalf("restored %d rules, want 3", adds)
	}
}

func TestPolicyRepairKeepsHealthyRulesAndRejectsConflict(t *testing.T) {
	s := backboneState(RoleIngress)
	r := &policyRunner{rules: fmt.Sprintf(`[
{"priority":80,"src":"all","fwmark":"0x4758","table":"main"},
{"priority":90,"src":"all","dst":%q,"table":"main"},
{"priority":100,"src":"all","uid_start":%d,"uid_end":%d,"table":"51820"}]`, s.Backbone.PeerEndpoint.Addr().String(), s.Backbone.IngressUID, s.Backbone.IngressUID)}
	a, _ := NewApplier(t.TempDir())
	a.runner = r
	if err := a.ensureIngressPolicy(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	for _, command := range r.commands {
		if len(command.args) > 0 && command.args[0] == "rule" {
			t.Fatalf("changed healthy rule: %v", command)
		}
	}
	r.commands = nil
	r.rules = `[{"priority":100,"src":"all","uid_start":1,"uid_end":1,"table":"main"}]`
	if err := a.ensureIngressPolicy(context.Background(), s); err == nil {
		t.Fatal("conflicting priority accepted")
	}
	if len(r.commands) != 0 {
		t.Fatal("modified runtime before rejecting conflict")
	}
}
