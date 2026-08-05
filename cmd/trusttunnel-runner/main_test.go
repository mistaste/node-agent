package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

const testDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestRunnerRejectsUnsafeManagedFilePermissions(t *testing.T) {
	root := t.TempDir()
	writeRunnerState(t, root, state{Version: 1, InboundID: "catalog-tt", Revision: 1, Digest: testDigest})
	for _, name := range []string{"vpn.toml", "hosts.toml", "credentials.toml"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(root, "credentials.toml"), 0640); err != nil {
		t.Fatal(err)
	}
	r := &runner{root: root, binary: "/bin/echo"}
	if err := r.reconcile(context.Background()); err == nil {
		t.Fatal("expected unsafe permissions to be rejected")
	}
	if r.running() {
		t.Fatal("runner started endpoint with unsafe credential permissions")
	}
}

func TestRunnerRestartsOnlyWhenStateKeyChanges(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shell fixture")
	}
	root := t.TempDir()
	starts := filepath.Join(root, "starts")
	binary := filepath.Join(root, "endpoint.sh")
	script := "#!/bin/sh\nprintf x >> " + strconv.Quote(starts) + "\ntrap 'exit 0' INT TERM\nwhile :; do sleep 1; done\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"vpn.toml", "hosts.toml", "credentials.toml"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeRunnerState(t, root, state{Version: 1, InboundID: "catalog-tt", Revision: 1, Digest: testDigest, ClientSetSHA256: "a"})
	r := &runner{root: root, binary: binary}
	ctx := context.Background()
	if err := r.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	waitForStarts(t, starts, 1)
	if err := r.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	waitForStarts(t, starts, 1)
	writeRunnerState(t, root, state{Version: 1, InboundID: "catalog-tt", Revision: 2, Digest: testDigest, ClientSetSHA256: "a"})
	if err := r.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	waitForStarts(t, starts, 2)
	r.stop(ctx)
}

func TestRunnerStopsWhenStateIsRemoved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shell fixture")
	}
	root := t.TempDir()
	binary := filepath.Join(root, "endpoint.sh")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\ntrap 'exit 0' INT TERM\nwhile :; do sleep 1; done\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"vpn.toml", "hosts.toml", "credentials.toml"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeRunnerState(t, root, state{Version: 1, InboundID: "catalog-tt", Revision: 1, Digest: testDigest})
	r := &runner{root: root, binary: binary}
	if err := r.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !r.running() {
		t.Fatal("runner did not start endpoint")
	}
	if err := os.Remove(filepath.Join(root, "state.json")); err != nil {
		t.Fatal(err)
	}
	if err := r.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.running() {
		t.Fatal("runner kept endpoint alive after tombstone removal")
	}
}

func writeRunnerState(t *testing.T, root string, value state) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "state.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func waitForStarts(t *testing.T, path string, expected int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(path)
		if len(raw) == expected {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	raw, _ := os.ReadFile(path)
	t.Fatalf("starts=%d want=%d", len(raw), expected)
}
