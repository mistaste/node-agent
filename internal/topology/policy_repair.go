package topology

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Repair missing runtime rules even if the durable revision and WG interface
// survived. Never delete a healthy rule or overwrite an unexpected owner.
func (a *Applier) ensureIngressPolicy(ctx context.Context, state DesiredState) error {
	output, err := a.runner.Output(ctx, "ip", "-j", "-4", "rule", "show")
	if err != nil {
		return fmt.Errorf("inspect ingress policy: %w", err)
	}
	var rules []struct {
		Priority int    `json:"priority"`
		Src      string `json:"src"`
		Dst      string `json:"dst"`
		Mark     string `json:"fwmark"`
		Table    string `json:"table"`
		UIDStart uint32 `json:"uid_start"`
		UIDEnd   uint32 `json:"uid_end"`
	}
	if err := json.Unmarshal(output, &rules); err != nil {
		return fmt.Errorf("decode ingress policy: %w", err)
	}
	b := state.Backbone
	wanted := map[int][]string{
		80:  {"fwmark", "0x4758", "lookup", "main"},
		90:  {"to", b.PeerEndpoint.Addr().String() + "/32", "lookup", "main"},
		100: {"uidrange", fmt.Sprintf("%d-%d", b.IngressUID, b.IngressUID), "lookup", policyTable},
	}
	seen := map[int]bool{}
	for _, rule := range rules {
		if _, owned := wanted[rule.Priority]; !owned {
			continue
		}
		valid := rule.Src == "all" && !seen[rule.Priority]
		switch rule.Priority {
		case 80:
			valid = valid && rule.Mark == "0x4758" && rule.Table == "main"
		case 90:
			valid = valid && strings.TrimSuffix(rule.Dst, "/32") == b.PeerEndpoint.Addr().String() && rule.Table == "main"
		case 100:
			valid = valid && rule.UIDStart == uint32(b.IngressUID) && rule.UIDEnd == uint32(b.IngressUID) && rule.Table == policyTable
		}
		if !valid {
			return fmt.Errorf("ingress policy priority %d conflicts with desired state", rule.Priority)
		}
		seen[rule.Priority] = true
	}
	// Atomic replace of the owned table's route; no interface teardown.
	if err := a.runner.Run(ctx, nil, "ip", "route", "replace", "default", "dev", b.InterfaceName, "table", policyTable); err != nil {
		return err
	}
	for _, priority := range []int{80, 90, 100} {
		if seen[priority] {
			continue
		}
		args := append([]string{"rule", "add", "priority", strconv.Itoa(priority)}, wanted[priority]...)
		if err := a.runner.Run(ctx, nil, "ip", args...); err != nil {
			return err
		}
	}
	return nil
}
