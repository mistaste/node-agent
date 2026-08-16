package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
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
}

type runner struct {
	root        string
	binary      string
	endpointUID uint32
	endpointGID uint32
	process     *exec.Cmd
	done        chan struct{}
	key         string
}

func main() {
	root := getenv("TRUSTTUNNEL_ROOT", "/data/trusttunnel")
	binary := getenv("TRUSTTUNNEL_BINARY", "/opt/trusttunnel/trusttunnel_endpoint")
	interval := parseDuration(getenv("TRUSTTUNNEL_RUNNER_INTERVAL", "2s"))
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
			r.stop(context.Background())
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
		r.stop(ctx)
		r.key = ""
		return nil
	}
	key := current.InboundID + ":" + current.Digest + ":" + current.ClientSetSHA256 + ":" + strconv.FormatInt(current.Revision, 10)
	if r.running() && r.key == key {
		return nil
	}
	r.stop(ctx)
	for _, name := range []string{"vpn.toml", "hosts.toml", "credentials.toml"} {
		if err := requireManagedFile(r.root, name, r.endpointGID); err != nil {
			return err
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
	log.Printf("[trusttunnel-runner] endpoint started")
	return nil
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

func (r *runner) stop(ctx context.Context) {
	if !r.running() {
		r.process = nil
		r.done = nil
		return
	}
	_ = r.process.Process.Signal(os.Interrupt)
	select {
	case <-r.done:
	case <-ctx.Done():
		_ = r.process.Process.Kill()
	case <-time.After(5 * time.Second):
		_ = r.process.Process.Kill()
	}
	r.process = nil
	r.done = nil
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
	if value.Version != 1 || strings.TrimSpace(value.InboundID) == "" || value.Revision < 1 || len(value.Digest) != 64 {
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
