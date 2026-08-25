package trusttunnel

import (
	"bytes"
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
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	stateVersion            = 1
	runnerStateFile         = "runner-state.json"
	externalRunnerReadyWait = 5 * time.Second
)

type endpointProcess interface {
	Stop(context.Context) error
	Running() bool
}

type processStarter interface {
	Start(string, ...string) (endpointProcess, error)
}

type osProcessStarter struct{}

type osEndpointProcess struct {
	cmd     *exec.Cmd
	done    chan struct{}
	mu      sync.RWMutex
	running bool
}

func (osProcessStarter) Start(name string, args ...string) (endpointProcess, error) {
	cmd := exec.Command(name, args...)
	// The endpoint must never inherit the agent's logs because they can contain
	// protocol details. The controller receives only allow-listed health data.
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	startedAt := time.Now()
	process := &osEndpointProcess{cmd: cmd, done: make(chan struct{}), running: true}
	go func() {
		err := cmd.Wait()
		process.mu.Lock()
		process.running = false
		process.mu.Unlock()
		close(process.done)
		// Wait errors contain only the local exit status/signal. Never attach
		// command arguments because their configuration files contain client
		// credentials. Unexpected exits must be visible to the controller logs;
		// otherwise the next reconciliation silently masks a crashing endpoint.
		if err != nil {
			log.Printf("[trusttunnel] endpoint exited after %s: %v", time.Since(startedAt).Round(time.Millisecond), err)
		} else {
			log.Printf("[trusttunnel] endpoint stopped after %s", time.Since(startedAt).Round(time.Millisecond))
		}
	}()
	return process, nil
}

func (p *osEndpointProcess) Running() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.running
}

func (p *osEndpointProcess) Stop(ctx context.Context) error {
	if !p.Running() {
		return nil
	}
	if err := p.cmd.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
		_ = p.cmd.Process.Kill()
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		_ = p.cmd.Process.Kill()
		return ctx.Err()
	}
}

type Runtime struct {
	root       string
	binary     string
	nodeSecret string
	starter    processStarter
	external   bool
	mu         sync.Mutex
	process    endpointProcess
}

type State struct {
	Version         int    `json:"version"`
	InboundID       string `json:"inbound_id"`
	Tag             string `json:"tag"`
	Revision        int64  `json:"revision"`
	Digest          string `json:"digest"`
	Port            int    `json:"port"`
	H3Port          int    `json:"h3_port,omitempty"`
	ClientCount     int    `json:"client_count"`
	ClientSetSHA256 string `json:"client_set_sha256"`
}

type ApplyRequest struct {
	InboundID       string
	Tag             string
	Revision        int64
	Endpoint        Endpoint
	ClientSetSHA256 string
}

// NewRuntime keeps the former service argument for source compatibility with
// deployed configuration. The endpoint is intentionally owned by node-agent:
// production node-agent runs in a container and cannot safely control host
// systemd. Docker stops both processes as one lifecycle unit.
func NewRuntime(root, binary, _ string, nodeSecret string) (*Runtime, error) {
	root = filepath.Clean(strings.TrimSpace(root))
	binary = filepath.Clean(strings.TrimSpace(binary))
	if !filepath.IsAbs(root) || !filepath.IsAbs(binary) {
		return nil, errors.New("TrustTunnel paths must be absolute")
	}
	if len(strings.TrimSpace(nodeSecret)) < 32 {
		return nil, errors.New("TrustTunnel requires the provisioned node secret")
	}
	return &Runtime{root: root, binary: binary, nodeSecret: nodeSecret, starter: osProcessStarter{}}, nil
}

func (r *Runtime) UseExternalProcess() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.external = true
	r.process = nil
}

func (r *Runtime) Available(ctx context.Context) bool {
	if info, err := os.Stat(r.binary); err != nil || info.IsDir() || info.Mode()&0111 == 0 {
		return false
	}
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return exec.CommandContext(checkCtx, r.binary, "--version").Run() == nil
}

func (r *Runtime) Apply(ctx context.Context, request ApplyRequest) (State, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if strings.TrimSpace(request.InboundID) == "" || strings.TrimSpace(request.Tag) == "" || request.Revision < 1 {
		return State{}, errors.New("TrustTunnel desired identity is invalid")
	}
	current, hasCurrent := r.State()
	if hasCurrent && strings.TrimSpace(current.InboundID) == strings.TrimSpace(request.InboundID) && request.Revision < current.Revision {
		return State{}, errors.New("TrustTunnel desired revision is stale")
	}
	primary := request.Endpoint
	var h3Files *Files
	// The SNI mux owns only TCP/443. TrustTunnel keeps H2 and H3 on its
	// private port; the bundle supervisor redirects public UDP/443 to it.
	files, err := BuildFiles(r.root, r.nodeSecret, primary)
	if err != nil {
		return State{}, err
	}
	digestFiles := []Files{files}
	state := State{Version: stateVersion, InboundID: request.InboundID, Tag: request.Tag, Revision: request.Revision, Digest: "", Port: request.Endpoint.Port, ClientCount: len(normalizeUUIDs(request.Endpoint.ClientUUIDs)), ClientSetSHA256: request.ClientSetSHA256}
	if h3Files != nil {
		digestFiles = append(digestFiles, *h3Files)
		state.H3Port = 443
	}
	state.Digest = bundleDigestAll(digestFiles...)
	if hasCurrent {
		contentUnchanged := current.InboundID == state.InboundID && current.Tag == state.Tag && current.Digest == state.Digest && current.ClientSetSHA256 == state.ClientSetSHA256
		healthy := (r.external && r.externalRunnerReady(current)) || (!r.external && r.process != nil && r.process.Running())
		if contentUnchanged && healthy {
			if current.Revision == state.Revision {
				return current, nil
			}
			if state.Revision > current.Revision {
				// A controller revision is acknowledgement metadata, not endpoint
				// configuration. Publish it without interrupting established sessions
				// when the rendered settings and exact client set are unchanged.
				stateRaw, marshalErr := json.Marshal(state)
				if marshalErr != nil {
					return State{}, errors.New("TrustTunnel state could not be encoded")
				}
				previousRaw, _ := json.Marshal(current)
				if writeErr := writeAtomic(filepath.Join(r.root, "state.json"), stateRaw, 0600); writeErr != nil {
					return State{}, writeErr
				}
				if r.external {
					if waitErr := r.waitForExternalRunner(ctx, state); waitErr != nil {
						_ = writeAtomic(filepath.Join(r.root, "state.json"), previousRaw, 0600)
						return State{}, waitErr
					}
				}
				return state, nil
			}
		}
		// Only categorical mismatch flags are logged. Digests, identities,
		// credentials and desired payloads remain private.
		log.Printf(
			"[trusttunnel] endpoint reconcile restart: identity=%t revision=%t config=%t clients=%t healthy=%t",
			current.InboundID == state.InboundID && current.Tag == state.Tag,
			current.Revision == state.Revision,
			current.Digest == state.Digest,
			current.ClientSetSHA256 == state.ClientSetSHA256,
			healthy,
		)
	} else {
		log.Printf("[trusttunnel] endpoint reconcile start: durable_state=false")
	}
	if err := os.MkdirAll(r.root, 0700); err != nil {
		return State{}, fmt.Errorf("create TrustTunnel root: %w", err)
	}
	previous := r.snapshot()
	if err := r.stopLocked(ctx); err != nil {
		return State{}, fmt.Errorf("stop previous TrustTunnel endpoint: %w", err)
	}
	for name, content := range map[string][]byte{"vpn.toml": files.Settings, "hosts.toml": files.Hosts, "credentials.toml": files.Credentials} {
		if err := writeAtomic(filepath.Join(r.root, name), content, 0600); err != nil {
			r.restore(previous)
			return State{}, err
		}
	}
	if h3Files != nil {
		for name, content := range map[string][]byte{"vpn-h3.toml": h3Files.Settings, "hosts-h3.toml": h3Files.Hosts} {
			if err := writeAtomic(filepath.Join(r.root, name), content, 0600); err != nil {
				r.restore(previous)
				return State{}, err
			}
		}
	} else {
		_ = os.Remove(filepath.Join(r.root, "vpn-h3.toml"))
		_ = os.Remove(filepath.Join(r.root, "hosts-h3.toml"))
	}
	if !r.external {
		if err := r.startAndCheckLocked(ctx, request.Endpoint.Port); err != nil {
			r.restore(previous)
			if old, ok := decodeState(previous["state.json"]); ok {
				_ = r.startAndCheckLocked(context.Background(), old.Port)
			}
			return State{}, err
		}
	}
	stateRaw, err := json.Marshal(state)
	if err != nil {
		_ = r.stopLocked(context.Background())
		r.restore(previous)
		return State{}, errors.New("TrustTunnel state could not be encoded")
	}
	if err := writeAtomic(filepath.Join(r.root, "state.json"), stateRaw, 0600); err != nil {
		_ = r.stopLocked(context.Background())
		r.restore(previous)
		return State{}, err
	}
	if r.external {
		if err := r.waitForExternalRunner(ctx, state); err != nil {
			r.restore(previous)
			return State{}, err
		}
	}
	return state, nil
}

func (r *Runtime) waitForExternalRunner(ctx context.Context, expected State) error {
	deadline := time.Now().Add(externalRunnerReadyWait)
	for {
		if r.externalRunnerReady(expected) {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("external TrustTunnel runner did not acknowledge the desired state")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (r *Runtime) externalRunnerReady(expected State) bool {
	raw, err := os.ReadFile(filepath.Join(r.root, runnerStateFile))
	if err != nil {
		return false
	}
	var observed State
	if json.Unmarshal(raw, &observed) != nil ||
		observed.Version != expected.Version ||
		observed.InboundID != expected.InboundID ||
		observed.Revision != expected.Revision ||
		observed.Digest != expected.Digest ||
		observed.ClientSetSHA256 != expected.ClientSetSHA256 {
		return false
	}
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(expected.Port)), 250*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (r *Runtime) Remove(ctx context.Context, inboundID string, revision int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.State()
	if !ok {
		return r.stopLocked(ctx)
	}
	if state.InboundID != strings.TrimSpace(inboundID) {
		return errors.New("TrustTunnel tombstone does not own the deployment")
	}
	if revision < state.Revision {
		return errors.New("TrustTunnel tombstone revision is stale")
	}
	if err := r.stopLocked(ctx); err != nil {
		return err
	}
	for _, name := range managedStateFiles {
		if err := os.Remove(filepath.Join(r.root, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove managed TrustTunnel file: %w", err)
		}
	}
	return nil
}

// Close stops the endpoint without deleting durable desired state. A restarted
// node-agent will reconcile the same state and launch it again if still desired.
func (r *Runtime) Close(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stopLocked(ctx)
}

func (r *Runtime) startAndCheckLocked(ctx context.Context, port int) error {
	if r.external {
		return nil
	}
	if err := ensurePortAvailable(port); err != nil {
		return err
	}
	process, err := r.starter.Start(r.binary, filepath.Join(r.root, "vpn.toml"), filepath.Join(r.root, "hosts.toml"))
	if err != nil {
		return fmt.Errorf("start TrustTunnel endpoint: %w", err)
	}
	r.process = process
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		if !process.Running() {
			r.process = nil
			return errors.New("TrustTunnel endpoint exited during startup")
		}
		probe, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		conn, dialErr := (&net.Dialer{}).DialContext(probe, "tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
		cancel()
		if dialErr == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			_ = r.stopLocked(context.Background())
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	_ = r.stopLocked(context.Background())
	return errors.New("TrustTunnel endpoint did not open its port")
}

func ensurePortAvailable(port int) error {
	listener, err := net.Listen("tcp4", net.JoinHostPort("0.0.0.0", fmt.Sprint(port)))
	if err != nil {
		return errors.New("TrustTunnel listener port is already in use")
	}
	if err := listener.Close(); err != nil {
		return errors.New("TrustTunnel listener port availability could not be verified")
	}
	return nil
}

func (r *Runtime) stopLocked(ctx context.Context) error {
	if r.external {
		r.process = nil
		return nil
	}
	if r.process == nil {
		return nil
	}
	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := r.process.Stop(stopCtx)
	r.process = nil
	return err
}

func (r *Runtime) State() (State, bool) {
	raw, err := os.ReadFile(filepath.Join(r.root, "state.json"))
	if err != nil {
		return State{}, false
	}
	return decodeState(raw)
}

func decodeState(raw []byte) (State, bool) {
	var state State
	if json.Unmarshal(raw, &state) != nil || state.Version != stateVersion || state.InboundID == "" || state.Tag == "" || state.Revision < 1 || state.Port < 1 {
		return State{}, false
	}
	return state, true
}

func (r *Runtime) snapshot() map[string][]byte {
	previous := make(map[string][]byte)
	for _, name := range managedStateFiles {
		if raw, err := os.ReadFile(filepath.Join(r.root, name)); err == nil {
			previous[name] = raw
		}
	}
	return previous
}

func (r *Runtime) restore(previous map[string][]byte) {
	for _, name := range managedStateFiles {
		path := filepath.Join(r.root, name)
		if content, ok := previous[name]; ok {
			_ = writeAtomic(path, content, 0600)
		} else {
			_ = os.Remove(path)
		}
	}
}

func writeAtomic(path string, content []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".guardex-trusttunnel-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

var managedStateFiles = []string{"vpn.toml", "hosts.toml", "credentials.toml", "vpn-h3.toml", "hosts-h3.toml", "state.json"}

func bundleDigest(files Files) string { return bundleDigestAll(files) }

func bundleDigestAll(files ...Files) string {
	hash := sha256.New()
	for _, bundle := range files {
		for _, raw := range [][]byte{bundle.Settings, bundle.Hosts, bundle.Credentials} {
			_, _ = hash.Write(raw)
			_, _ = hash.Write([]byte{0})
		}
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func safeCommandError(output []byte) string {
	value := strings.TrimSpace(string(bytes.ToValidUTF8(output, []byte("?"))))
	if value == "" {
		return "command returned a non-zero status"
	}
	if len(value) > 256 {
		value = value[:256]
	}
	return value
}
