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
	r := &runner{root: root, caddy: getenv("CADDY_BINARY", "/usr/bin/caddy"), haproxy: getenv("HAPROXY_BINARY", "/usr/sbin/haproxy")}
	if err := r.run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal("[transport-bundle-runner] stopped")
	}
}

type runner struct {
	root, caddy, haproxy string
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
		return nil
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
		r.caddyProcess, err = start(r.caddy, "run", "--config", caddyConfig, "--adapter", "caddyfile")
	} else {
		err = exec.CommandContext(ctx, r.caddy, "reload", "--config", caddyConfig, "--adapter", "caddyfile", "--address", "127.0.0.1:2019").Run()
	}
	if err != nil || !waitTCP(ctx, loopback(state.NaivePort), 3*time.Second) || !waitTCP(ctx, loopback(state.DecoyPort), 3*time.Second) || !waitTCP(ctx, loopback(state.TrustTunnelPort), 3*time.Second) {
		return errors.New("private transport listeners are not ready")
	}
	if err := r.ensureUDPRedirect(ctx, state.TrustTunnelPort); err != nil {
		return errors.New("public QUIC redirect is not ready")
	}
	if running(r.haproxyProcess) {
		_ = stop(r.haproxyProcess)
	}
	r.haproxyProcess, err = start(r.haproxy, "-W", "-db", "-f", haproxyConfig)
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
	_ = exec.CommandContext(ctx, "iptables", "-t", "nat", "-N", "GUARDEX_TT_H3").Run()
	if exec.CommandContext(ctx, "iptables", "-t", "nat", "-F", "GUARDEX_TT_H3").Run() != nil ||
		exec.CommandContext(ctx, "iptables", "-t", "nat", "-A", "GUARDEX_TT_H3", "-p", "udp", "-j", "REDIRECT", "--to-ports", strconv.Itoa(port)).Run() != nil {
		return errors.New("configure UDP redirect chain")
	}
	jump := redirectJumpArgs("-C")
	if exec.CommandContext(ctx, "iptables", jump...).Run() != nil {
		if exec.CommandContext(ctx, "iptables", redirectJumpArgs("-A")...).Run() != nil {
			return errors.New("install UDP redirect jump")
		}
	}
	r.udpRedirectPort = port
	return nil
}

func (r *runner) removeUDPRedirect() {
	for exec.Command("iptables", redirectJumpArgs("-C")...).Run() == nil {
		if exec.Command("iptables", redirectJumpArgs("-D")...).Run() != nil {
			break
		}
	}
	_ = exec.Command("iptables", "-t", "nat", "-F", "GUARDEX_TT_H3").Run()
	_ = exec.Command("iptables", "-t", "nat", "-X", "GUARDEX_TT_H3").Run()
	r.udpRedirectPort = 0
}

func redirectJumpArgs(action string) []string {
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
