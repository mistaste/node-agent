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
