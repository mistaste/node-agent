package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/guardex/node-agent/internal/transportbundle"
)

func TestRedirectArgsAreScopedToUDP443(t *testing.T) {
	want := []string{"-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", "443", "-m", "comment", "--comment", "guardex-tt-h3-mux", "-j", "REDIRECT", "--to-ports", "18443"}
	if got := redirectArgs("-A", 18443); !reflect.DeepEqual(got, want) {
		t.Fatalf("redirect args = %#v, want %#v", got, want)
	}
}

func TestPlanKeepsHAProxyRunningForCaddyOnlyChange(t *testing.T) {
	plan := planReconcile(true, true, "old-caddy", "new-caddy", "same-haproxy", "same-haproxy")
	if !plan.applyCaddy {
		t.Fatal("Caddy credential change was not scheduled for reload")
	}
	if plan.applyHAProxy {
		t.Fatal("Caddy-only change unnecessarily scheduled HAProxy restart")
	}
}

func TestPlanRestartsOnlyChangedOrMissingComponent(t *testing.T) {
	tests := []struct {
		name                   string
		caddyRunning           bool
		haproxyRunning         bool
		appliedCaddy           string
		desiredCaddy           string
		appliedHAProxy         string
		desiredHAProxy         string
		wantCaddy, wantHAProxy bool
	}{
		{name: "unchanged", caddyRunning: true, haproxyRunning: true, appliedCaddy: "c", desiredCaddy: "c", appliedHAProxy: "h", desiredHAProxy: "h"},
		{name: "haproxy changed", caddyRunning: true, haproxyRunning: true, appliedCaddy: "c", desiredCaddy: "c", appliedHAProxy: "old", desiredHAProxy: "new", wantHAProxy: true},
		{name: "caddy missing", haproxyRunning: true, appliedCaddy: "c", desiredCaddy: "c", appliedHAProxy: "h", desiredHAProxy: "h", wantCaddy: true},
		{name: "haproxy missing", caddyRunning: true, appliedCaddy: "c", desiredCaddy: "c", appliedHAProxy: "h", desiredHAProxy: "h", wantHAProxy: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := planReconcile(test.caddyRunning, test.haproxyRunning, test.appliedCaddy, test.desiredCaddy, test.appliedHAProxy, test.desiredHAProxy)
			if plan.applyCaddy != test.wantCaddy || plan.applyHAProxy != test.wantHAProxy {
				t.Fatalf("plan = %+v, want caddy=%t haproxy=%t", plan, test.wantCaddy, test.wantHAProxy)
			}
		})
	}
}

func TestReconcileForcesRetryAfterAmbiguousCaddyReloadFailure(t *testing.T) {
	root := t.TempDir()
	haproxyRaw := []byte("unchanged-haproxy")
	caddyRaw := []byte("new-caddy")
	haproxyDigestRaw := sha256.Sum256(haproxyRaw)
	caddyDigestRaw := sha256.Sum256(caddyRaw)
	bundleDigestRaw := sha256.Sum256(append(append([]byte(nil), haproxyRaw...), caddyRaw...))
	state := transportbundle.State{
		Version: 1, InboundID: "naive-id", Tag: "gx-naive", Revision: 2,
		Digest:          hex.EncodeToString(bundleDigestRaw[:]),
		HAProxyDigest:   hex.EncodeToString(haproxyDigestRaw[:]),
		CaddyDigest:     hex.EncodeToString(caddyDigestRaw[:]),
		TrustTunnelPort: 8443, NaivePort: 9443, DecoyPort: 9080,
	}
	stateRaw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{
		"haproxy.cfg": haproxyRaw,
		"Caddyfile":   caddyRaw,
		"state.json":  stateRaw,
	} {
		if err := os.WriteFile(filepath.Join(root, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	caddy := filepath.Join(root, "caddy")
	haproxy := filepath.Join(root, "haproxy")
	if err := os.WriteFile(caddy, []byte("#!/bin/sh\n[ \"$1\" = reload ] && exit 1\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(haproxy, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	r := &runner{
		root: root, caddy: caddy, haproxy: haproxy,
		caddyProcess: &child{running: true}, haproxyProcess: &child{running: true},
		appliedDigest: "old-bundle", appliedCaddyDigest: "old-caddy",
		appliedHAProxyDigest: state.HAProxyDigest,
	}
	if err := r.reconcile(context.Background()); err == nil {
		t.Fatal("expected Caddy reload failure")
	}
	if r.appliedCaddyDigest != "" {
		t.Fatalf("ambiguous Caddy reload kept trusted digest %q", r.appliedCaddyDigest)
	}
}
