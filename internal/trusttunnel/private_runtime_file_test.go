package trusttunnel

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPrivateRuntimeFileRequiresExactProtectedRegularFile(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "credentials")
	want := []byte("private fixture")
	for _, mode := range []os.FileMode{0600, 0640} {
		if err := os.WriteFile(path, want, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if !samePrivateRuntimeFile(path, want) {
			t.Fatalf("rejected approved mode %o", mode)
		}
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if samePrivateRuntimeFile(path, want) {
		t.Fatal("accepted public credentials")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if samePrivateRuntimeFile(path, want[:len(want)-1]) {
		t.Fatal("accepted longer content")
	}
	if err := os.Chmod(root, 0770); err != nil {
		t.Fatal(err)
	}
	if samePrivateRuntimeFile(path, want) {
		t.Fatal("accepted group-writable parent")
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if samePrivateRuntimeFile(link, want) {
		t.Fatal("accepted symlink")
	}
	if samePrivateRuntimeFile(filepath.Join(root, "missing"), want) {
		t.Fatal("accepted absent file")
	}
}

func TestAcknowledgedExternalApplyPreservesPrivateFilesAndRequiresNewAck(t *testing.T) {
	runtime, starter, request := newFixedRuntime(t)
	defer starter.close()
	initial, err := runtime.Apply(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	runtime.UseExternalProcess()
	if err := os.Chmod(runtime.root, 0750); err != nil {
		t.Fatal(err)
	}
	ack := initial
	ack.CredentialReloadVersion = 1
	raw, _ := json.Marshal(ack)
	if err := os.WriteFile(filepath.Join(runtime.root, runnerStateFile), raw, 0600); err != nil {
		t.Fatal(err)
	}
	credentials := filepath.Join(runtime.root, "credentials.toml")
	statePath := filepath.Join(runtime.root, "state.json")
	if err := os.Chmod(credentials, 0640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(credentials)
	if err != nil {
		t.Fatal(err)
	}
	stateBefore, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		got, err := runtime.Apply(context.Background(), request)
		if err != nil || got != initial {
			t.Fatalf("unchanged apply: %v", err)
		}
	}
	after, _ := os.Stat(credentials)
	stateAfter, _ := os.Stat(statePath)
	if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || after.Mode().Perm() != 0640 {
		t.Fatal("unchanged credentials replaced or permissions changed")
	}
	if !os.SameFile(stateBefore, stateAfter) || !stateBefore.ModTime().Equal(stateAfter.ModTime()) {
		t.Fatal("unchanged state replaced")
	}
	request.Revision++
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := runtime.Apply(ctx, request); err == nil {
		t.Fatal("new revision accepted without runner acknowledgment")
	}
	current, _ := runtime.State()
	if current != initial {
		t.Fatal("unacknowledged revision persisted")
	}
}

func TestExternalApplyRepairsCredentialDriftDespiteMatchingAcknowledgment(t *testing.T) {
	for _, drift := range []string{"content", "public", "missing", "symlink"} {
		t.Run(drift, func(t *testing.T) {
			runtime, starter, request := newFixedRuntime(t)
			defer starter.close()
			initial, err := runtime.Apply(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			runtime.UseExternalProcess()
			if err := os.Chmod(runtime.root, 0750); err != nil {
				t.Fatal(err)
			}
			ack := initial
			ack.CredentialReloadVersion = 1
			raw, _ := json.Marshal(ack)
			if err := os.WriteFile(filepath.Join(runtime.root, runnerStateFile), raw, 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(runtime.root, "credentials.toml")
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch drift {
			case "content":
				err = os.WriteFile(path, []byte("stale"), 0600)
			case "public":
				err = os.Chmod(path, 0644)
			case "missing":
				err = os.Remove(path)
			case "symlink":
				target := filepath.Join(runtime.root, "old-credentials")
				if err = os.Rename(path, target); err == nil {
					err = os.Symlink(target, path)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := runtime.Apply(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			if !samePrivateRuntimeFile(path, want) {
				t.Fatal("credential drift was not repaired")
			}
			if starter.starts != 1 {
				t.Fatal("repair restarted endpoint")
			}
		})
	}
}
