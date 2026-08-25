package transportbundle

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimePublishesRestrictedBundleAndWaitsForRunner(t *testing.T) {
	root := t.TempDir()
	runtime, err := NewRuntime(root, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	request := ApplyRequest{InboundID: "naive-id", Tag: "gx-naive", Revision: 2, ClientSetSHA256: "clients", Config: Config{PublicPort: 443, TrustTunnelHostname: "node.example.com", TrustTunnelPort: 8443, NaiveHostname: "naive.node.example.com", NaivePort: 9443, DecoyPort: 9080, CertificateFile: "/cert", PrivateKeyFile: "/key", ClientUUIDs: []string{testUUID}}}
	go func() {
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			raw, readErr := os.ReadFile(filepath.Join(root, "state.json"))
			if readErr != nil {
				continue
			}
			var state State
			if json.Unmarshal(raw, &state) == nil {
				_ = os.WriteFile(filepath.Join(root, "runner-state.json"), raw, 0600)
				return
			}
		}
	}()
	state, err := runtime.Apply(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if state.Revision != 2 || state.ClientCount != 1 || state.Digest == "" || state.HAProxyDigest == "" || state.CaddyDigest == "" {
		t.Fatalf("state = %+v", state)
	}
	if state.HAProxyDigest == state.CaddyDigest {
		t.Fatal("component config digests unexpectedly match")
	}
	for _, name := range []string{"haproxy.cfg", "Caddyfile", "state.json"} {
		info, statErr := os.Stat(filepath.Join(root, name))
		if statErr != nil {
			t.Fatalf("stat %s: %v", name, statErr)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode = %v", name, info.Mode().Perm())
		}
	}
}

func TestRuntimeRestoresPreviousBundleWhenRunnerRejectsUpdate(t *testing.T) {
	root := t.TempDir()
	runtime, err := NewRuntime(root, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	runtime.readyWait = 25 * time.Millisecond
	for name, content := range map[string]string{"haproxy.cfg": "old-haproxy", "Caddyfile": "old-caddy", "state.json": `{"version":1,"inbound_id":"old","tag":"gx-old","revision":1,"digest":"old"}`} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	request := ApplyRequest{InboundID: "naive-id", Tag: "gx-naive", Revision: 2, ClientSetSHA256: "clients", Config: Config{PublicPort: 443, TrustTunnelHostname: "node.example.com", TrustTunnelPort: 8443, NaiveHostname: "naive.node.example.com", NaivePort: 9443, DecoyPort: 9080, CertificateFile: "/cert", PrivateKeyFile: "/key", ClientUUIDs: []string{testUUID}}}
	if _, err := runtime.Apply(context.Background(), request); err == nil {
		t.Fatal("expected runner acknowledgement timeout")
	}
	for name, expected := range map[string]string{"haproxy.cfg": "old-haproxy", "Caddyfile": "old-caddy"} {
		raw, readErr := os.ReadFile(filepath.Join(root, name))
		if readErr != nil || string(raw) != expected {
			t.Fatalf("%s was not restored", name)
		}
	}
}

func TestRuntimeRejectsSameInboundRevisionDowngradeBeforeMutation(t *testing.T) {
	root := t.TempDir()
	runtime, err := NewRuntime(root, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	current := State{Version: runtimeStateVersion, InboundID: "naive-id", Tag: "gx-naive", Revision: 5, Digest: "current"}
	currentRaw, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "state.json"), currentRaw, 0600); err != nil {
		t.Fatal(err)
	}
	request := ApplyRequest{InboundID: "naive-id", Tag: "gx-naive", Revision: 4}
	if _, err := runtime.Apply(context.Background(), request); err == nil {
		t.Fatal("expected stale revision to be rejected")
	}
	after, err := os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(currentRaw) {
		t.Fatal("stale revision mutated durable state")
	}
	for _, name := range []string{"haproxy.cfg", "Caddyfile"} {
		if _, err := os.Stat(filepath.Join(root, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale revision created %s: %v", name, err)
		}
	}
}
