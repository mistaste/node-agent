package topology

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const ingressUDPSourcePriority = "95"
const ingressUDPSourceOwner = "242"

// The read-only runner acknowledgement identifies the active state.json.
// Older runners do not include its listening port in their acknowledgement.
// No credentials or new backend/runner fields are required.
func (a *Applier) SetTrustTunnelStatePath(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("TrustTunnel state path must be absolute")
	}
	a.trustTunnelStatePath = filepath.Clean(path)
	return nil
}

type ingressUDPSourceRule struct {
	uid  uint32
	port int
}
type ingressUDPSourcePlan struct {
	runner   commandRunner
	desired  ingressUDPSourceRule
	existing []ingressUDPSourceRule
}

func (a *Applier) prepareIngressUDPSourcePolicy(ctx context.Context, state DesiredState, previousUID ...uint32) (*ingressUDPSourcePlan, error) {
	if a.trustTunnelStatePath == "" || state.Backbone == nil || !state.Enabled {
		return nil, nil
	}
	raw, err := os.ReadFile(a.trustTunnelStatePath)
	if errors.Is(err, os.ErrNotExist) {
		// The runner temporarily removes its acknowledgement during startup.
		// Keep the last owned route; its firewall exception is still reply-only.
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("TrustTunnel runner state could not be read")
	}
	type identity struct {
		Version         int    `json:"version"`
		InboundID       string `json:"inbound_id"`
		Revision        int64  `json:"revision"`
		Digest          string `json:"digest"`
		ClientSetSHA256 string `json:"client_set_sha256"`
	}
	var ack identity
	valid := func(v identity) bool {
		return v.Version == 1 && v.InboundID != "" && v.Revision > 0 && len(v.Digest) == 64
	}
	if len(raw) > 16384 || json.Unmarshal(raw, &ack) != nil || !valid(ack) {
		return nil, errors.New("TrustTunnel runner state is invalid")
	}
	raw, err = os.ReadFile(filepath.Join(filepath.Dir(a.trustTunnelStatePath), "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("TrustTunnel endpoint state could not be read")
	}
	var endpoint struct {
		identity
		Port int `json:"port"`
	}
	if len(raw) > 16384 || json.Unmarshal(raw, &endpoint) != nil || !valid(endpoint.identity) || endpoint.Port < 1 || endpoint.Port > 65535 {
		return nil, errors.New("TrustTunnel endpoint state is invalid")
	}
	if ack != endpoint.identity {
		// Atomic files may be observed between controller publication and runner
		// acknowledgement. Never route using a port that is not yet active.
		return nil, nil
	}
	uid := state.Backbone.IngressUID
	rules, err := a.ingressUDPSourceRules(ctx, append([]uint32{uid}, previousUID...)...)
	if err != nil {
		return nil, err
	}
	return &ingressUDPSourcePlan{runner: a.runner, desired: ingressUDPSourceRule{uid, endpoint.Port}, existing: rules}, nil
}

func (a *Applier) ensureIngressUDPSourcePolicy(ctx context.Context, state DesiredState) error {
	plan, err := a.prepareIngressUDPSourcePolicy(ctx, state)
	if err != nil {
		return err
	}
	_, err = plan.apply(ctx)
	return err
}

// apply returns an exact undo journal. Failed replacement restores deleted old
// selectors before withdrawing a newly added selector; no broad priority delete.
func (plan *ingressUDPSourcePlan) apply(ctx context.Context) (func(context.Context) error, error) {
	var undo [][]string
	rollback := func(ctx context.Context) error {
		var failures []error
		for i := len(undo) - 1; i >= 0; i-- {
			if err := plan.runner.Run(ctx, nil, "ip", undo[i]...); err != nil {
				failures = append(failures, err)
			}
		}
		return errors.Join(failures...)
	}
	if plan == nil {
		return func(context.Context) error { return nil }, nil
	}
	fail := func(err error) (func(context.Context) error, error) {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return nil, errors.Join(err, rollback(rollbackCtx))
	}
	found := false
	for _, rule := range plan.existing {
		found = found || rule == plan.desired
	}
	if !found {
		// Add the new exact selector first. Changing metadata never tears down
		// WireGuard, the TT process, TCP connections or unrelated policy rules.
		if err := plan.runner.Run(ctx, nil, "ip", ingressUDPSourceArgs("add", plan.desired.uid, plan.desired.port)...); err != nil {
			return fail(err)
		}
		undo = append(undo, ingressUDPSourceArgs("del", plan.desired.uid, plan.desired.port))
	}
	kept := false
	for _, rule := range plan.existing {
		if rule == plan.desired && !kept {
			kept = true
			continue
		}
		if err := plan.runner.Run(ctx, nil, "ip", ingressUDPSourceArgs("del", rule.uid, rule.port)...); err != nil {
			return fail(err)
		}
		undo = append(undo, ingressUDPSourceArgs("add", rule.uid, rule.port))
	}
	return rollback, nil
}

func ingressUDPSourceArgs(action string, uid uint32, port int) []string {
	return []string{"rule", action, "priority", ingressUDPSourcePriority,
		"uidrange", fmt.Sprintf("%d-%d", uid, uid), "ipproto", "udp", "sport", strconv.Itoa(port),
		"lookup", "main", "protocol", ingressUDPSourceOwner}
}

func (a *Applier) ingressUDPSourceRules(ctx context.Context, uids ...uint32) ([]ingressUDPSourceRule, error) {
	raw, err := a.runner.Output(ctx, "ip", "-j", "-4", "rule", "show")
	if err != nil {
		return nil, err
	}
	var rules []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, err
	}
	var result []ingressUDPSourceRule
	for _, rule := range rules {
		value := func(key string) string { return strings.Trim(string(rule[key]), "\"") }
		if value("priority") != ingressUDPSourcePriority {
			continue
		}
		// Reject unknown ownership/selectors rather than deleting an operator's
		// policy at the same priority. Explicit protocol tags survive restarts.
		allowed := map[string]bool{"priority": true, "src": true, "table": true, "protocol": true,
			"uid_start": true, "uid_end": true, "ipproto": true, "sport": true}
		for key := range rule {
			if !allowed[key] {
				return nil, errors.New("ingress UDP source policy conflicts with another owner")
			}
		}
		port, parseErr := strconv.Atoi(value("sport"))
		uid, uidErr := strconv.ParseUint(value("uid_start"), 10, 32)
		uidAllowed := false
		for _, expected := range uids {
			uidAllowed = uidAllowed || uid == uint64(expected)
		}
		if value("src") != "all" || value("table") != "main" || value("protocol") != ingressUDPSourceOwner ||
			uidErr != nil || !uidAllowed || value("uid_end") != value("uid_start") ||
			value("ipproto") != "udp" || parseErr != nil || port < 1 || port > 65535 {
			return nil, errors.New("ingress UDP source policy conflicts with another owner")
		}
		result = append(result, ingressUDPSourceRule{uint32(uid), port})
	}
	return result, nil
}

func (a *Applier) removeIngressUDPSourcePolicy(ctx context.Context, uid uint32) error {
	if a.trustTunnelStatePath == "" {
		return nil
	}
	rules, err := a.ingressUDPSourceRules(ctx, uid)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if err := a.runner.Run(ctx, nil, "ip", ingressUDPSourceArgs("del", rule.uid, rule.port)...); err != nil {
			return err
		}
	}
	return nil
}
