package main

import (
	"reflect"
	"testing"
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
