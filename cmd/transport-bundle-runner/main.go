package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/guardex/node-agent/internal/transportbundle"
)

type child struct {
	cmd     *exec.Cmd
	done    chan error
	mu      sync.RWMutex
	running bool
}

func main() {
	root := filepath.Clean(getenv("TRANSPORT_BUNDLE_ROOT", "/data/transport-bundle"))
	if !filepath.IsAbs(root) {
		log.Fatal("[transport-bundle-runner] root must be absolute")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	r := &runner{
		root: root, caddy: getenv("CADDY_BINARY", "/usr/bin/caddy"),
		haproxy:  getenv("HAPROXY_BINARY", "/usr/sbin/haproxy"),
		caddyUID: uint32(getenvInt("CADDY_UID", 65532)),
		caddyGID: uint32(getenvInt("CADDY_GID", 65532)),
	}
	if err := r.run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal("[transport-bundle-runner] stopped")
	}
}

type runner struct {
	root, caddy, haproxy string
	caddyUID, caddyGID   uint32
	caddyProcess         *child
	haproxyProcess       *child
	appliedDigest        string
	udpRedirectPort      int
}

func (r *runner) run(ctx context.Context) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	defer r.stopChildren()
	for {
		if err := r.reconcile(ctx); err != nil {
			log.Printf("[transport-bundle-runner] reconcile deferred: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (r *runner) reconcile(ctx context.Context) error {
	stateRaw, err := os.ReadFile(filepath.Join(r.root, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		r.stopChildren()
		r.appliedDigest = ""
		_ = os.Remove(filepath.Join(r.root, "runner-state.json"))
		return nil
	}
	if err != nil {
		return err
	}
	var state transportbundle.State
	if json.Unmarshal(stateRaw, &state) != nil || state.Version != 1 || state.Digest == "" || !internalPort(state.TrustTunnelPort) || !internalPort(state.NaivePort) || !internalPort(state.DecoyPort) {
		return errors.New("invalid desired state")
	}
	if state.Digest == r.appliedDigest && running(r.caddyProcess) && running(r.haproxyProcess) {
		// The rendered bundle can stay byte-for-byte identical while the
		// controller advances its revision or membership acknowledgement. Keep
		// the processes running, but acknowledge the exact desired state so the
		// controller does not time out and incorrectly restore public TT/443.
		if err := r.ensureUDPRedirect(ctx, state.TrustTunnelPort); err != nil {
			return errors.New("public QUIC redirect is not ready")
		}
		return writeAtomic(filepath.Join(r.root, "runner-state.json"), stateRaw, 0600)
	}
	haproxyConfig := filepath.Join(r.root, "haproxy.cfg")
	caddyConfig := filepath.Join(r.root, "Caddyfile")
	haproxyRaw, err := os.ReadFile(haproxyConfig)
	if err != nil {
		return err
	}
	caddyRaw, err := os.ReadFile(caddyConfig)
	if err != nil {
		return err
	}
	digestRaw := append(append([]byte(nil), haproxyRaw...), caddyRaw...)
	digest := sha256.Sum256(digestRaw)
	if !strings.EqualFold(state.Digest, hex.EncodeToString(digest[:])) {
		return errors.New("bundle digest mismatch")
	}
	if exec.CommandContext(ctx, r.caddy, "validate", "--config", caddyConfig, "--adapter", "caddyfile").Run() != nil {
		return errors.New("Caddy validation failed")
	}
	if exec.CommandContext(ctx, r.haproxy, "-c", "-f", haproxyConfig).Run() != nil {
		return errors.New("HAProxy validation failed")
	}
	// Caddy owns only private listeners and is made ready before public 443.
	if !running(r.caddyProcess) {
		if err = prepareCaddyRuntime(caddyConfig, r.caddyGID); err == nil {
			r.caddyProcess, err = startAs(r.caddyUID, r.caddyGID, r.caddy, "run", "--config", caddyConfig, "--adapter", "caddyfile")
		}
	} else {
		err = exec.CommandContext(ctx, r.caddy, "reload", "--config", caddyConfig, "--adapter", "caddyfile", "--address", "127.0.0.1:2019").Run()
	}
	if err != nil || !waitTCP(ctx, loopback(state.NaivePort), 3*time.Second) || !waitTCP(ctx, loopback(state.DecoyPort), 3*time.Second) {
		return errors.New("private transport listeners are not ready")
	}
	if err := r.ensureUDPRedirect(ctx, state.TrustTunnelPort); err != nil {
		return errors.New("public QUIC redirect is not ready")
	}
	if running(r.haproxyProcess) {
		_ = stop(r.haproxyProcess)
	}
	// Keep HAProxy as one foreground child owned by this runner. Master-worker
	// mode can detach the process tracked by os/exec inside a container, which
	// makes every reconciliation look like a crash and churn the public mux.
	r.haproxyProcess, err = start(r.haproxy, "-db", "-f", haproxyConfig)
	if err != nil || !waitTCP(ctx, "127.0.0.1:443", 3*time.Second) {
		return errors.New("public mux listener is not ready")
	}
	if err := writeAtomic(filepath.Join(r.root, "runner-state.json"), stateRaw, 0600); err != nil {
		return err
	}
	r.appliedDigest = state.Digest
	log.Printf("[transport-bundle-runner] bundle active")
	return nil
}

func internalPort(port int) bool { return port >= 1024 && port <= 65535 && port != 443 }

func loopback(port int) string { return net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)) }

func start(name string, args ...string) (*child, error) {
	cmd := exec.Command(name, args...)
	return startCommand(cmd)
}

func startAs(uid, gid uint32, name string, args ...string) (*child, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true},
	}
	return startCommand(cmd)
}

func startCommand(cmd *exec.Cmd) (*child, error) {
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &child{cmd: cmd, done: make(chan error, 1), running: true}
	go func() {
		err := cmd.Wait()
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
		c.done <- err
	}()
	return c, nil
}

func prepareCaddyRuntime(config string, gid uint32) error {
	configDirectory := filepath.Dir(config)
	if err := os.Chmod(configDirectory, 0750); err != nil {
		return err
	}
	if err := os.Chown(configDirectory, os.Geteuid(), int(gid)); err != nil {
		return err
	}
	if err := os.Chmod(config, 0640); err != nil {
		return err
	}
	if err := os.Chown(config, os.Geteuid(), int(gid)); err != nil {
		return err
	}
	for _, directory := range []string{"/config", "/data/caddy"} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			return err
		}
		if err := os.Chmod(directory, 0700); err != nil {
			return err
		}
		if err := os.Chown(directory, int(gid), int(gid)); err != nil {
			return err
		}
	}
	return nil
}

func running(c *child) bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

func stop(c *child) error {
	if !running(c) {
		return nil
	}
	_ = c.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-c.done:
		return nil
	case <-time.After(3 * time.Second):
		return c.cmd.Process.Kill()
	}
}

func (r *runner) stopChildren() {
	_ = stop(r.haproxyProcess)
	_ = stop(r.caddyProcess)
	r.removeUDPRedirect()
	r.haproxyProcess, r.caddyProcess = nil, nil
}

func (r *runner) ensureUDPRedirect(ctx context.Context, port int) error {
	if r.udpRedirectPort != 0 && r.udpRedirectPort != port {
		r.removeUDPRedirect()
	}
	removeLegacyUDPRedirect()
	rule := redirectArgs("-C", port)
	if exec.CommandContext(ctx, "iptables", rule...).Run() != nil {
		if exec.CommandContext(ctx, "iptables", redirectArgs("-A", port)...).Run() != nil {
			return errors.New("install UDP redirect")
		}
	}
	r.udpRedirectPort = port
	return nil
}

func (r *runner) removeUDPRedirect() {
	if r.udpRedirectPort != 0 {
		for exec.Command("iptables", redirectArgs("-C", r.udpRedirectPort)...).Run() == nil {
			if exec.Command("iptables", redirectArgs("-D", r.udpRedirectPort)...).Run() != nil {
				break
			}
		}
	}
	removeLegacyUDPRedirect()
	r.udpRedirectPort = 0
}

func removeLegacyUDPRedirect() {
	for exec.Command("iptables", legacyRedirectJumpArgs("-C")...).Run() == nil {
		if exec.Command("iptables", legacyRedirectJumpArgs("-D")...).Run() != nil {
			break
		}
	}
	_ = exec.Command("iptables", "-t", "nat", "-F", "GUARDEX_TT_H3").Run()
	_ = exec.Command("iptables", "-t", "nat", "-X", "GUARDEX_TT_H3").Run()
}

func redirectArgs(action string, port int) []string {
	return []string{"-t", "nat", action, "PREROUTING", "-p", "udp", "--dport", "443", "-m", "comment", "--comment", "guardex-tt-h3-mux", "-j", "REDIRECT", "--to-ports", strconv.Itoa(port)}
}

func legacyRedirectJumpArgs(action string) []string {
	return []string{"-t", "nat", action, "PREROUTING", "-p", "udp", "--dport", "443", "-m", "comment", "--comment", "guardex-tt-h3-mux", "-j", "GUARDEX_TT_H3"}
}

func waitTCP(ctx context.Context, address string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := (&net.Dialer{Timeout: 200 * time.Millisecond}).DialContext(ctx, "tcp", address)
		if err == nil {
			_ = conn.Close()
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(50 * time.Millisecond):
		}
	}
	return false
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".runner-state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(mode); err == nil {
		_, err = tmp.Write(data)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || value < 1 || value > 1<<31-1 {
		return fallback
	}
	return value
}
