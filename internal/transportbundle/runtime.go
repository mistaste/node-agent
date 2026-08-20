package transportbundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const runtimeStateVersion = 1

type Runtime struct {
	root       string
	nodeSecret string
	readyWait  time.Duration
	mu         sync.Mutex
}

type ApplyRequest struct {
	InboundID       string
	Tag             string
	Revision        int64
	Config          Config
	ClientSetSHA256 string
}

type State struct {
	Version         int    `json:"version"`
	InboundID       string `json:"inbound_id"`
	Tag             string `json:"tag"`
	Revision        int64  `json:"revision"`
	Digest          string `json:"digest"`
	ClientCount     int    `json:"client_count"`
	ClientSetSHA256 string `json:"client_set_sha256"`
}

func NewRuntime(root, nodeSecret string) (*Runtime, error) {
	root = filepath.Clean(strings.TrimSpace(root))
	if !filepath.IsAbs(root) || len(strings.TrimSpace(nodeSecret)) < 32 {
		return nil, errors.New("transport bundle runtime configuration is invalid")
	}
	return &Runtime{root: root, nodeSecret: nodeSecret, readyWait: 5 * time.Second}, nil
}

func (r *Runtime) Apply(ctx context.Context, request ApplyRequest) (State, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if strings.TrimSpace(request.InboundID) == "" || strings.TrimSpace(request.Tag) == "" || request.Revision < 1 {
		return State{}, errors.New("transport bundle desired identity is invalid")
	}
	files, err := Build(r.nodeSecret, request.Config)
	if err != nil {
		return State{}, err
	}
	digestRaw := append(append([]byte(nil), files.HAProxy...), files.Caddy...)
	digest := sha256.Sum256(digestRaw)
	state := State{Version: runtimeStateVersion, InboundID: request.InboundID, Tag: request.Tag, Revision: request.Revision, Digest: hex.EncodeToString(digest[:]), ClientCount: len(normalizeUUIDs(request.Config.ClientUUIDs)), ClientSetSHA256: request.ClientSetSHA256}
	stateRaw, err := json.Marshal(state)
	if err != nil {
		return State{}, errors.New("transport bundle state could not be encoded")
	}
	if err := os.MkdirAll(r.root, 0700); err != nil {
		return State{}, errors.New("transport bundle root could not be created")
	}
	previous := r.snapshot()
	for name, content := range map[string][]byte{"haproxy.cfg": files.HAProxy, "Caddyfile": files.Caddy, "state.json": stateRaw} {
		if err := writeAtomic(filepath.Join(r.root, name), content, 0600); err != nil {
			r.restore(previous)
			return State{}, err
		}
	}
	active, err := r.waitForRunner(ctx, state)
	if err != nil {
		r.restore(previous)
		return State{}, err
	}
	return active, nil
}

func (r *Runtime) snapshot() map[string][]byte {
	result := make(map[string][]byte, 3)
	for _, name := range []string{"haproxy.cfg", "Caddyfile", "state.json"} {
		if raw, err := os.ReadFile(filepath.Join(r.root, name)); err == nil {
			result[name] = raw
		}
	}
	return result
}

func (r *Runtime) restore(snapshot map[string][]byte) {
	for _, name := range []string{"haproxy.cfg", "Caddyfile", "state.json"} {
		if raw, ok := snapshot[name]; ok {
			_ = writeAtomic(filepath.Join(r.root, name), raw, 0600)
		} else {
			_ = os.Remove(filepath.Join(r.root, name))
		}
	}
}

func (r *Runtime) Remove(_ context.Context, inboundID string, revision int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.State()
	if !ok {
		return nil
	}
	if current.InboundID != strings.TrimSpace(inboundID) || revision < current.Revision {
		return errors.New("transport bundle tombstone does not own current state")
	}
	return os.Remove(filepath.Join(r.root, "state.json"))
}

func (r *Runtime) State() (State, bool) {
	raw, err := os.ReadFile(filepath.Join(r.root, "state.json"))
	if err != nil {
		return State{}, false
	}
	var state State
	if json.Unmarshal(raw, &state) != nil || state.Version != runtimeStateVersion || state.InboundID == "" || state.Revision < 1 {
		return State{}, false
	}
	return state, true
}

func (r *Runtime) waitForRunner(ctx context.Context, expected State) (State, error) {
	deadline := time.NewTimer(r.readyWait)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		raw, err := os.ReadFile(filepath.Join(r.root, "runner-state.json"))
		if err == nil {
			var observed State
			if json.Unmarshal(raw, &observed) == nil && observed.InboundID == expected.InboundID && observed.Revision == expected.Revision && observed.Digest == expected.Digest && observed.ClientSetSHA256 == expected.ClientSetSHA256 {
				return expected, nil
			}
		}
		select {
		case <-ctx.Done():
			return State{}, ctx.Err()
		case <-deadline.C:
			return State{}, errors.New("transport bundle runner did not acknowledge desired state")
		case <-ticker.C:
		}
	}
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".guardex-bundle-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(mode); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}
