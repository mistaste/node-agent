package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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

func TestRunnerPreparesPrivateEndpointTreeForDedicatedIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX ownership")
	}
	root := t.TempDir()
	certs := filepath.Join(root, "certs")
	if err := os.Mkdir(certs, 0755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(root, "vpn.toml"),
		filepath.Join(root, "hosts.toml"),
		filepath.Join(root, "credentials.toml"),
		filepath.Join(certs, "fullchain.pem"),
		filepath.Join(certs, "privkey.pem"),
	} {
		if err := os.WriteFile(path, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	r := &runner{
		root: root, endpointUID: uint32(os.Getuid()), endpointGID: uint32(os.Getgid()),
	}
	if r.endpointUID == 0 {
		// UID zero intentionally bypasses dedicated-identity permissions.
		// A root-run test must still exercise the non-root endpoint branch.
		r.endpointUID = 65532
	}
	if err := r.prepareEndpointAccess(); err != nil {
		t.Fatal(err)
	}
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		want := os.FileMode(0640)
		if info.IsDir() {
			want = 0750
		}
		if info.Mode().Perm() != want {
			t.Fatalf("mode %o for %s, want %o", info.Mode().Perm(), path, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerAcknowledgesRevisionOnlyChangeWithoutRestart(t *testing.T) {
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
	if _, err := os.Stat(filepath.Join(root, runnerStateFile)); err != nil {
		t.Fatalf("runner did not publish readiness state: %v", err)
	}
	if err := r.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	waitForStarts(t, starts, 1)
	writeRunnerState(t, root, state{Version: 1, InboundID: "catalog-tt", Revision: 2, Digest: testDigest, ClientSetSHA256: "a"})
	if err := r.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	waitForStarts(t, starts, 1)
	raw, err := os.ReadFile(filepath.Join(root, runnerStateFile))
	if err != nil {
		t.Fatal(err)
	}
	var acknowledged state
	if json.Unmarshal(raw, &acknowledged) != nil || acknowledged.Revision != 2 {
		t.Fatalf("runner acknowledgement = %s", raw)
	}
	r.stop(ctx)
}

func TestDesiredProcessKeyTracksH3LifecycleButNotRevision(t *testing.T) {
	base := state{InboundID: "catalog-tt", Revision: 1, Digest: testDigest, ClientSetSHA256: "clients"}
	revisionOnly := base
	revisionOnly.Revision++
	if desiredProcessKey(base) != desiredProcessKey(revisionOnly) {
		t.Fatal("revision-only change altered process key")
	}
	withH3 := base
	withH3.H3Port = 443
	if desiredProcessKey(base) == desiredProcessKey(withH3) {
		t.Fatal("H3 lifecycle change did not alter process key")
	}
}

func TestRunnerStartsSplitHTTP2AndHTTP3Endpoints(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shell fixture")
	}
	root := t.TempDir()
	starts := filepath.Join(root, "split-starts")
	binary := filepath.Join(root, "endpoint.sh")
	script := "#!/bin/sh\nprintf x >> " + strconv.Quote(starts) + "\ntrap 'exit 0' INT TERM\nwhile :; do sleep 1; done\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"vpn.toml", "hosts.toml", "credentials.toml", "vpn-h3.toml", "hosts-h3.toml"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeRunnerState(t, root, state{Version: 1, InboundID: "catalog-tt", Revision: 1, Digest: testDigest, H3Port: 443})
	r := &runner{root: root, binary: binary}
	if err := r.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitForStarts(t, starts, 2)
	if !r.running() || !r.h3Running() {
		t.Fatal("split endpoints are not both running")
	}
	if err := r.stop(context.Background()); err != nil {
		t.Fatal(err)
	}
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
	if _, err := os.Stat(filepath.Join(root, runnerStateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runner readiness state survived endpoint removal: %v", err)
	}
}

func TestExitedEndpointCannotMarkReplacementStopped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shell fixture")
	}
	process := exec.Command("/bin/sh", "-c", "sleep 0.05")
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	oldDone := make(chan struct{})
	replacementDone := make(chan struct{})
	r := &runner{done: replacementDone}
	go r.waitEndpoint(process, oldDone, time.Now())
	select {
	case <-oldDone:
	case <-time.After(time.Second):
		t.Fatal("old endpoint waiter did not finish")
	}
	select {
	case <-replacementDone:
		t.Fatal("old endpoint waiter marked the replacement stopped")
	default:
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

func TestLiveCredentialReloadKeepsProcessAndRequiresEndpointAcknowledgement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX process fixture")
	}
	root := t.TempDir()
	binary := filepath.Join(root, "endpoint.sh")
	script := "#!/bin/sh\ntrap 'exit 0' INT TERM\nwhile :; do sleep 1; done\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"vpn.toml", "hosts.toml", "credentials.toml"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("first"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	current := state{Version: 1, InboundID: "tt", Revision: 1, Digest: testDigest, ClientSetSHA256: "first"}
	writeRunnerState(t, root, current)
	r := &runner{root: root, binary: binary, credentialReload: true}
	defer r.stop(context.Background())
	// Simulate the endpoint acknowledging actual bytes, independently of state.json.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				raw, err := os.ReadFile(filepath.Join(root, "credentials.toml"))
				if err != nil {
					continue
				}
				digest := sha256.Sum256(raw)
				_ = os.WriteFile(filepath.Join(root, "credentials-applied", "h2.sha256"), []byte(hex.EncodeToString(digest[:])), 0600)
			}
		}
	}()
	if err := r.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	pid := r.process.Process.Pid
	current.Revision++
	current.ClientSetSHA256 = "second"
	current.Digest = strings.Repeat("b", 64)
	if err := os.WriteFile(filepath.Join(root, "credentials.toml"), []byte("second"), 0600); err != nil {
		t.Fatal(err)
	}
	writeRunnerState(t, root, current)
	if err := r.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.process.Process.Pid != pid {
		t.Fatal("credential change restarted endpoint")
	}
	raw, _ := os.ReadFile(filepath.Join(root, runnerStateFile))
	var acknowledged state
	if json.Unmarshal(raw, &acknowledged) != nil || acknowledged.ClientSetSHA256 != "second" || acknowledged.CredentialReloadVersion != 1 {
		t.Fatalf("not acknowledged: %s", raw)
	}
	cancel()
	<-watchDone
	// A live but non-acknowledging endpoint must not be reported current or restarted.
	if err := os.WriteFile(filepath.Join(root, "credentials.toml"), []byte("third"), 0600); err != nil {
		t.Fatal(err)
	}
	current.Revision++
	current.ClientSetSHA256 = "third"
	writeRunnerState(t, root, current)
	short, cancelShort := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancelShort()
	if err := r.reconcile(short); err == nil {
		t.Fatal("missing endpoint acknowledgement accepted")
	}
	if r.process.Process.Pid != pid {
		t.Fatal("failed reload restarted other sessions")
	}
}

func TestRunnerHonorsDefaultReconciliationInterval(t *testing.T) {
	if got := parseDuration("250ms"); got != 250*time.Millisecond {
		t.Fatalf("default interval silently changed: %s", got)
	}
	for _, input := range []string{"invalid", "0s", "1ms"} {
		if got := parseDuration(input); got != 250*time.Millisecond {
			t.Fatalf("unsafe retry interval for %q: %s", input, got)
		}
	}
}

func TestCredentialReloadVersions(t *testing.T) {
	for version, want := range map[string]bool{"1.1.0-guardex-live-credentials.1": true, "1.1.0-guardex-account-qos.1": true, "1.1.0": false, "unexpected": false} {
		if got := supportsCredentialReload(version); got != want {
			t.Errorf("%q: got %v", version, got)
		}
	}
}
