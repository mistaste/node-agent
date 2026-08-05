package topology

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

const policyTable = "51820"

type commandRunner interface {
	Run(context.Context, []byte, string, ...string) error
}
type osRunner struct{}

func (osRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s failed: %w (%s)", filepath.Base(name), err, strings.TrimSpace(string(output)))
	}
	return nil
}

type Applier struct {
	root   string
	runner commandRunner
}

func NewApplier(root string) (*Applier, error) {
	root = filepath.Clean(strings.TrimSpace(root))
	if !filepath.IsAbs(root) {
		return nil, errors.New("topology root must be absolute")
	}
	return &Applier{root: root, runner: osRunner{}}, nil
}

func (a *Applier) PublicKey() (string, error) {
	private, err := a.ensurePrivateKey()
	if err != nil {
		return "", err
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(public), nil
}

func (a *Applier) Apply(ctx context.Context, state DesiredState) error {
	if err := Validate(state); err != nil {
		return err
	}
	current, _ := a.loadState()
	if current.Revision > state.Revision {
		return ErrUnsafeDesiredState
	}
	if current.Revision == state.Revision {
		oldJSON, _ := json.Marshal(current)
		newJSON, _ := json.Marshal(state)
		if bytes.Equal(oldJSON, newJSON) {
			return nil
		}
		return fmt.Errorf("%w: desired state changed without revision", ErrUnsafeDesiredState)
	}
	if !state.Enabled {
		if err := a.removeOwned(ctx, current); err != nil {
			return err
		}
		return a.saveState(state)
	}
	if state.Backbone != nil {
		if err := a.applyWireGuard(ctx, state); err != nil {
			return err
		}
	}
	rules, err := RenderNFTables(state)
	if err != nil {
		return err
	}
	transaction := ""
	if a.runner.Run(ctx, nil, "nft", "list", "table", "inet", TableName) == nil {
		transaction = "delete table inet " + TableName + "\n"
	}
	transaction += rules
	if err := a.runner.Run(ctx, []byte(transaction), "nft", "-c", "-f", "-"); err != nil {
		return err
	}
	if err := a.runner.Run(ctx, []byte(transaction), "nft", "-f", "-"); err != nil {
		return err
	}
	return a.saveState(state)
}

func (a *Applier) applyWireGuard(ctx context.Context, state DesiredState) error {
	b := state.Backbone
	private, err := a.ensurePrivateKey()
	if err != nil {
		return err
	}
	keyPath := filepath.Join(a.root, "wireguard.key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(private)+"\n"), 0600); err != nil {
		return err
	}
	if a.runner.Run(ctx, nil, "ip", "link", "show", "dev", b.InterfaceName) != nil {
		if err := a.runner.Run(ctx, nil, "ip", "link", "add", "dev", b.InterfaceName, "type", "wireguard"); err != nil {
			return err
		}
	}
	commands := [][]string{
		{"ip", "address", "replace", b.TunnelAddress.String(), "dev", b.InterfaceName},
		{"wg", "set", b.InterfaceName, "private-key", keyPath, "listen-port", strconv.Itoa(b.ListenPort), "peer", b.PeerPublicKey, "endpoint", b.PeerEndpoint.String(), "allowed-ips", "0.0.0.0/0,::/0", "persistent-keepalive", "25"},
		{"ip", "link", "set", "up", "dev", b.InterfaceName},
	}
	if state.Role == RoleIngress {
		commands = append(commands,
			[]string{"ip", "route", "replace", "default", "dev", b.InterfaceName, "table", policyTable},
			[]string{"ip", "rule", "replace", "priority", "100", "uidrange", fmt.Sprintf("%d-%d", b.IngressUID, b.IngressUID), "lookup", policyTable})
	} else {
		commands = append(commands, []string{"sysctl", "-w", "net.ipv4.ip_forward=1"})
	}
	for _, command := range commands {
		if err := a.runner.Run(ctx, nil, command[0], command[1:]...); err != nil {
			return err
		}
	}
	return nil
}

func (a *Applier) removeOwned(ctx context.Context, current DesiredState) error {
	if a.runner.Run(ctx, nil, "nft", "list", "table", "inet", TableName) == nil {
		if err := a.runner.Run(ctx, []byte("delete table inet "+TableName+"\n"), "nft", "-f", "-"); err != nil {
			return err
		}
	}
	if current.Backbone != nil {
		if current.Role == RoleIngress {
			_ = a.runner.Run(ctx, nil, "ip", "rule", "del", "priority", "100")
		}
		_ = a.runner.Run(ctx, nil, "ip", "link", "del", "dev", current.Backbone.InterfaceName)
	}
	return nil
}

func (a *Applier) ensurePrivateKey() ([]byte, error) {
	if err := os.MkdirAll(a.root, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(a.root, "wireguard.raw")
	if value, err := os.ReadFile(path); err == nil && len(value) == curve25519.ScalarSize {
		return value, nil
	}
	value := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	value[0] &= 248
	value[31] &= 127
	value[31] |= 64
	tmp, err := os.CreateTemp(a.root, ".wg-key-")
	if err != nil {
		return nil, err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(value); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(name, path); err != nil {
		return nil, err
	}
	return value, nil
}

func (a *Applier) loadState() (DesiredState, error) {
	var state DesiredState
	raw, err := os.ReadFile(filepath.Join(a.root, "state.json"))
	if err != nil {
		return state, err
	}
	err = json.Unmarshal(raw, &state)
	return state, err
}
func (a *Applier) saveState(state DesiredState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(a.root, ".state-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(raw)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(a.root, "state.json"))
}
