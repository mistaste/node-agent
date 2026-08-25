package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type state struct {
	Version         int    `json:"version"`
	InboundID       string `json:"inbound_id"`
	Revision        int64  `json:"revision"`
	Digest          string `json:"digest"`
	ClientSetSHA256 string `json:"client_set_sha256"`
	H3Port          int    `json:"h3_port,omitempty"`
}

const runnerStateFile = "runner-state.json"

type runner struct {
	root        string
	binary      string
	endpointUID uint32
	endpointGID uint32
	process     *exec.Cmd
	done        chan struct{}
	h3Process   *exec.Cmd
	h3Done      chan struct{}
	key         string
}

func main() {
	root := getenv("TRUSTTUNNEL_ROOT", "/data/trusttunnel")
	binary := getenv("TRUSTTUNNEL_BINARY", "/opt/trusttunnel/trusttunnel_endpoint")
	interval := parseDuration(getenv("TRUSTTUNNEL_RUNNER_INTERVAL", "250ms"))
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	r := &runner{
		root: filepath.Clean(root), binary: filepath.Clean(binary),
		endpointUID: 65532, endpointGID: 65532,
	}
	if !filepath.IsAbs(r.root) || !filepath.IsAbs(r.binary) {
		log.Fatal("[trusttunnel-runner] root and binary must be absolute")
	}
	log.Printf("[trusttunnel-runner] watching %s", r.root)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := r.reconcile(ctx); err != nil {
			log.Printf("[trusttunnel-runner] reconcile failed: %v", err)
		}
		select {
		case <-ctx.Done():
			_ = r.stop(context.Background())
			return
		case <-ticker.C:
		}
	}
}

func (r *runner) reconcile(ctx context.Context) error {
	current, ok, err := r.loadState()
	if err != nil {
		return err
	}
	if !ok {
		r.clearRunnerState()
		if err := r.stop(ctx); err != nil {
			return err
		}
		r.key = ""
		return nil
	}
	// Revision is controller acknowledgement metadata. The endpoint only needs
	// a restart when its identity, rendered configuration, or exact client set
	// changes; runner-state still acknowledges every newer revision below.
	key := current.InboundID + ":" + current.Digest + ":" + current.ClientSetSHA256
	if r.running() && (current.H3Port == 0 || r.h3Running()) && r.key == key {
		if err := r.writeRunnerState(current); err != nil {
			return err
		}
		return nil
	}
	r.clearRunnerState()
	if err := r.stop(ctx); err != nil {
		return err
	}
	for _, name := range []string{"vpn.toml", "hosts.toml", "credentials.toml"} {
		if err := requireManagedFile(r.root, name, r.endpointGID); err != nil {
			return err
		}
	}
	if current.H3Port != 0 {
		for _, name := range []string{"vpn-h3.toml", "hosts-h3.toml"} {
			if err := requireManagedFile(r.root, name, r.endpointGID); err != nil {
				return err
			}
		}
	}
	if err := r.prepareEndpointAccess(); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, r.binary, filepath.Join(r.root, "vpn.toml"), filepath.Join(r.root, "hosts.toml"))
	if r.endpointUID != 0 {
		if err := configureEndpointCommand(cmd, r.endpointUID, r.endpointGID); err != nil {
			return err
		}
	}
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return err
	}
	r.process = cmd
	done := make(chan struct{})
	r.done = done
	r.key = key
	go r.waitEndpoint(cmd, done, time.Now())
	if current.H3Port != 0 {
		h3 := exec.CommandContext(ctx, r.binary, filepath.Join(r.root, "vpn-h3.toml"), filepath.Join(r.root, "hosts-h3.toml"))
		// The public QUIC listener requires NET_BIND_SERVICE. Keep only this
		// pinned H3 endpoint under the container's capability-bounded root;
		// the TCP endpoint continues to run as the dedicated unprivileged UID.
		// The container is read-only, no-new-privileges, and exposes no Docker
		// socket, so this does not grant host-level privilege.
		h3.Stdout, h3.Stderr = nil, nil
		if err := h3.Start(); err != nil {
			_ = r.stop(context.Background())
			return err
		}
		r.h3Process = h3
		r.h3Done = make(chan struct{})
		go r.waitEndpoint(h3, r.h3Done, time.Now())
		time.Sleep(250 * time.Millisecond)
		if !r.running() || !r.h3Running() {
			_ = r.stop(context.Background())
			return errors.New("split TrustTunnel endpoint exited during startup")
		}
	}
	if err := r.writeRunnerState(current); err != nil {
		_ = r.stop(context.Background())
		return err
	}
	log.Printf("[trusttunnel-runner] endpoint started")
	return nil
}

func (r *runner) writeRunnerState(current state) error {
	raw, err := json.Marshal(current)
	if err != nil {
		return errors.New("encode runner state")
	}
	target := filepath.Join(r.root, runnerStateFile)
	temporary := target + ".tmp"
	if err := os.WriteFile(temporary, raw, 0640); err != nil {
		return fmt.Errorf("write runner state: %w", err)
	}
	if r.endpointGID != 0 {
		if err := os.Chown(temporary, os.Geteuid(), int(r.endpointGID)); err != nil {
			_ = os.Remove(temporary)
			return fmt.Errorf("own runner state: %w", err)
		}
	}
	if err := os.Rename(temporary, target); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("publish runner state: %w", err)
	}
	return nil
}

func (r *runner) clearRunnerState() {
	_ = os.Remove(filepath.Join(r.root, runnerStateFile))
}

func (r *runner) waitEndpoint(process *exec.Cmd, processDone chan struct{}, startedAt time.Time) {
	err := process.Wait()
	if err != nil {
		log.Printf("[trusttunnel-runner] endpoint exited after %s: %v", time.Since(startedAt).Round(time.Millisecond), err)
	} else {
		log.Printf("[trusttunnel-runner] endpoint stopped after %s", time.Since(startedAt).Round(time.Millisecond))
	}
	close(processDone)
}

func (r *runner) prepareEndpointAccess() error {
	if r.endpointUID == 0 {
		return nil
	}
	return filepath.Walk(r.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("managed TrustTunnel tree contains a symlink")
		}
		owner := os.Geteuid()
		if err := os.Chown(path, owner, int(r.endpointGID)); err != nil {
			return err
		}
		if info.IsDir() {
			return os.Chmod(path, 0750)
		}
		return os.Chmod(path, 0640)
	})
}

func (r *runner) stop(ctx context.Context) error {
	r.clearRunnerState()
	if err := stopProcess(ctx, r.h3Process, r.h3Done); err != nil {
		return err
	}
	r.h3Process, r.h3Done = nil, nil
	if !r.running() {
		r.process = nil
		r.done = nil
		return nil
	}
	if err := r.process.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("signal endpoint: %w", err)
	}
	select {
	case <-r.done:
	case <-ctx.Done():
		if err := r.process.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("kill endpoint after cancellation: %w", err)
		}
	case <-time.After(5 * time.Second):
		if err := r.process.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("kill endpoint after timeout: %w", err)
		}
	}
	r.process = nil
	r.done = nil
	return nil
}

func stopProcess(ctx context.Context, process *exec.Cmd, done chan struct{}) error {
	if process == nil || done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	default:
	}
	if err := process.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("signal endpoint: %w", err)
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return process.Process.Kill()
	case <-time.After(5 * time.Second):
		return process.Process.Kill()
	}
}

func (r *runner) running() bool {
	if r.process == nil || r.done == nil {
		return false
	}
	select {
	case <-r.done:
		return false
	default:
		return true
	}
}

func (r *runner) h3Running() bool {
	if r.h3Process == nil || r.h3Done == nil {
		return false
	}
	select {
	case <-r.h3Done:
		return false
	default:
		return true
	}
}

func (r *runner) loadState() (state, bool, error) {
	raw, err := os.ReadFile(filepath.Join(r.root, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return state{}, false, nil
	}
	if err != nil {
		return state{}, false, err
	}
	var value state
	if err := json.Unmarshal(raw, &value); err != nil {
		return state{}, false, err
	}
	if value.Version != 1 || strings.TrimSpace(value.InboundID) == "" || value.Revision < 1 || len(value.Digest) != 64 || value.H3Port != 0 && value.H3Port != 443 {
		return state{}, false, errors.New("invalid durable TrustTunnel state")
	}
	return value, true, nil
}

func requireManagedFile(root, name string, endpointGID uint32) error {
	path := filepath.Join(root, name)
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() || info.Mode().Perm()&0007 != 0 {
		return errors.New("managed TrustTunnel file has unsafe permissions")
	}
	if info.Mode().Perm()&0070 != 0 {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || endpointGID == 0 || uint32(stat.Gid) != endpointGID || info.Mode().Perm() != 0640 {
			return errors.New("managed TrustTunnel file has unsafe group access")
		}
	}
	return nil
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func parseDuration(value string) time.Duration {
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 500*time.Millisecond {
		return 2 * time.Second
	}
	return duration
}
