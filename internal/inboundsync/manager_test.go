package inboundsync

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardex/node-agent/internal/inbound"
	"github.com/guardex/node-agent/internal/store"
)

func managerControllerState(id string, revision int64, clientSeed string) store.InboundControllerState {
	digest := sha256.Sum256([]byte(clientSeed))
	return store.InboundControllerState{
		InboundID:              id,
		DesiredRevision:        revision,
		AppliedRevision:        revision,
		Status:                 "active",
		PublicMaterialJSON:     json.RawMessage(`{"public_key":"public"}`),
		ClientParamsJSON:       json.RawMessage(`{}`),
		AppliedClientCount:     1,
		AppliedClientSetSHA256: fmt.Sprintf("%x", digest[:]),
	}
}

type fakeCore struct {
	mu                sync.Mutex
	inbounds          map[string][]byte
	addFailure        error
	partialAddFailure bool
	removeCalls       []string
}

func newFakeCore() *fakeCore { return &fakeCore{inbounds: make(map[string][]byte)} }

func (f *fakeCore) AddInboundFromJSON(_ context.Context, raw []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addFailure != nil {
		if f.partialAddFailure {
			cfg, err := inbound.Parse(raw)
			if err != nil {
				return err
			}
			f.inbounds[cfg.Tag] = append([]byte(nil), raw...)
		}
		return f.addFailure
	}
	cfg, err := inbound.Parse(raw)
	if err != nil {
		return err
	}
	if _, exists := f.inbounds[cfg.Tag]; exists {
		return errors.New("already exists")
	}
	f.inbounds[cfg.Tag] = append([]byte(nil), raw...)
	return nil
}

func (f *fakeCore) RemoveInbound(_ context.Context, tag string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removeCalls = append(f.removeCalls, tag)
	if _, exists := f.inbounds[tag]; !exists {
		return errors.New("not found")
	}
	delete(f.inbounds, tag)
	return nil
}

func (f *fakeCore) ListInboundTags(_ context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tags := make([]string, 0, len(f.inbounds))
	for tag := range f.inbounds {
		tags = append(tags, tag)
	}
	return tags, nil
}

func managerConfig(t *testing.T, tag string, port int) inbound.Config {
	t.Helper()
	raw := fmt.Sprintf(`{
		"tag":%q,"port":%d,"protocol":"vless",
		"settings":{"clients":[],"decryption":"none"},
		"streamSettings":{"network":"tcp","security":"reality","realitySettings":{
			"dest":"www.example.com:443","serverNames":["www.example.com"],
			"privateKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortIds":["0123456789abcdef"]
		}}
	}`, tag, port)
	cfg, err := inbound.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestManagerApplyIsDurableIdempotentAndReplaceable(t *testing.T) {
	inventory := store.NewInboundStore(filepath.Join(t.TempDir(), "inbounds.json"))
	core := newFakeCore()
	manager := New(core, inventory, time.Minute)
	ctx := context.Background()

	first := managerConfig(t, "dynamic", 8443)
	if err := manager.Apply(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(ctx, first); err != nil {
		t.Fatalf("idempotent Apply: %v", err)
	}
	replacement := managerConfig(t, "dynamic", 9443)
	if err := manager.Apply(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	record, ok := inventory.Get("dynamic")
	if !ok || record.Config.Digest != replacement.Digest {
		t.Fatalf("stored replacement = %+v, ok=%v", record.Config.Public(), ok)
	}
	items := manager.Inventory()
	if len(items) != 1 || !items[0].Applied || items[0].Port != 9443 {
		t.Fatalf("inventory = %+v", items)
	}
}

func TestManagerBootstrapRestoresBeforeUsersCanSync(t *testing.T) {
	inventory := store.NewInboundStore(filepath.Join(t.TempDir(), "inbounds.json"))
	cfg := managerConfig(t, "restore-me", 8443)
	if _, err := inventory.Put(cfg); err != nil {
		t.Fatal(err)
	}
	core := newFakeCore()
	manager := New(core, inventory, time.Minute)
	applied, failed := manager.Bootstrap(context.Background())
	if applied != 1 || failed != 0 {
		t.Fatalf("bootstrap applied=%d failed=%d", applied, failed)
	}
	if _, ok := core.inbounds[cfg.Tag]; !ok {
		t.Fatal("stored inbound was not restored")
	}
}

func TestManagerNeverDeletesStaticInbound(t *testing.T) {
	inventory := store.NewInboundStore(filepath.Join(t.TempDir(), "inbounds.json"))
	staleDesired := managerConfig(t, "vless-in", 8443)
	if _, err := inventory.Put(staleDesired); err != nil {
		t.Fatal(err)
	}
	core := newFakeCore()
	core.inbounds["vless-in"] = []byte("static config is owned by xray-config.json")
	manager := New(core, inventory, time.Minute, "vless-in", "api")
	if applied, failed := manager.Reconcile(context.Background()); applied != 0 || failed != 1 {
		t.Fatalf("protected reconcile applied=%d failed=%d", applied, failed)
	}
	err := manager.Remove(context.Background(), "vless-in")
	if !errors.Is(err, ErrNotManaged) {
		t.Fatalf("Remove static error = %v, want ErrNotManaged", err)
	}
	if len(core.removeCalls) != 0 {
		t.Fatalf("core removal was called for static inbound: %v", core.removeCalls)
	}
	if err := manager.Apply(context.Background(), staleDesired); !errors.Is(err, ErrTagConflict) {
		t.Fatalf("Apply protected error = %v, want ErrTagConflict", err)
	}
}

func TestManagerDoesNotClaimUnmanagedRuntimeTag(t *testing.T) {
	inventory := store.NewInboundStore(filepath.Join(t.TempDir(), "inbounds.json"))
	core := newFakeCore()
	cfg := managerConfig(t, "occupied", 8443)
	core.inbounds[cfg.Tag] = cfg.Raw
	manager := New(core, inventory, time.Minute)
	if err := manager.Apply(context.Background(), cfg); !errors.Is(err, ErrTagConflict) {
		t.Fatalf("Apply occupied error = %v, want ErrTagConflict", err)
	}
	if _, ok := inventory.Get(cfg.Tag); ok {
		t.Fatal("unmanaged runtime inbound was persisted as managed")
	}
	if len(core.removeCalls) != 0 {
		t.Fatalf("ownership preflight removed an unmanaged runtime tag: %v", core.removeCalls)
	}
}

func TestManagerCleansOnlyHandlerProvenCreatedByFailedAdd(t *testing.T) {
	inventory := store.NewInboundStore(filepath.Join(t.TempDir(), "inbounds.json"))
	core := newFakeCore()
	core.addFailure = errors.New("core failed after registration")
	core.partialAddFailure = true
	manager := New(core, inventory, time.Minute, "vless-in", "api")
	cfg := managerConfig(t, "partial", 8443)
	if err := manager.Apply(context.Background(), cfg); err == nil {
		t.Fatal("partially failed Add unexpectedly succeeded")
	}
	if _, exists := core.inbounds[cfg.Tag]; exists {
		t.Fatal("handler proven absent before Add remained after partial failure")
	}
	if len(core.removeCalls) != 1 || core.removeCalls[0] != cfg.Tag {
		t.Fatalf("cleanup calls = %v", core.removeCalls)
	}
}

func TestInventoryJSONNeverLeaksPrivateConfig(t *testing.T) {
	inventory := store.NewInboundStore(filepath.Join(t.TempDir(), "inbounds.json"))
	manager := New(newFakeCore(), inventory, time.Minute)
	cfg := managerConfig(t, "no-leak", 8443)
	if err := manager.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(manager.Inventory())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") || strings.Contains(string(body), "privateKey") {
		t.Fatalf("inventory leaked private config: %s", body)
	}
}

func TestManagerKeepsDesiredStateWhenCoreRejectsReconcile(t *testing.T) {
	inventory := store.NewInboundStore(filepath.Join(t.TempDir(), "inbounds.json"))
	cfg := managerConfig(t, "temporarily-down", 8443)
	if _, err := inventory.Put(cfg); err != nil {
		t.Fatal(err)
	}
	core := newFakeCore()
	core.addFailure = errors.New("core unavailable")
	manager := New(core, inventory, time.Minute)
	_, failed := manager.Reconcile(context.Background())
	if failed != 1 {
		t.Fatalf("failed count = %d, want 1", failed)
	}
	items := manager.Inventory()
	if len(items) != 1 || !items[0].Desired || items[0].Applied || items[0].LastError == "" {
		t.Fatalf("inventory = %+v", items)
	}
}

func TestManagerRollsBackRuntimeWhenPersistenceFails(t *testing.T) {
	inventory := store.NewInboundStore("")
	core := newFakeCore()
	manager := New(core, inventory, time.Minute)
	cfg := managerConfig(t, "rollback", 8443)
	if err := manager.Apply(context.Background(), cfg); err == nil {
		t.Fatal("Apply unexpectedly succeeded with a broken store")
	}
	if _, exists := core.inbounds[cfg.Tag]; exists {
		t.Fatal("runtime inbound remained after persistence failure")
	}
	if len(inventory.All()) != 0 {
		t.Fatal("desired inventory changed after persistence failure")
	}
}

func TestControllerRevisionLedgerRejectsStaleMutationAndProtectsLegacyAPI(t *testing.T) {
	inventory := store.NewInboundStore(filepath.Join(t.TempDir(), "inbounds.json"))
	core := newFakeCore()
	manager := New(core, inventory, time.Minute, "vless-in", "api")
	ctx := context.Background()
	first := managerConfig(t, "gx-controller-owned", 8443)
	state5 := managerControllerState("catalog-owned", 5, "clients-a")
	if _, err := manager.ApplyControllerDesiredWithResult(ctx, first, first.Digest, state5); err != nil {
		t.Fatal(err)
	}

	changedClients := managerControllerState("catalog-owned", 5, "clients-b")
	structuralChanged, err := manager.ApplyControllerDesiredWithResult(ctx, first, first.Digest, changedClients)
	if err != nil || structuralChanged {
		t.Fatalf("same structural revision client observation changed structure=%v err=%v", structuralChanged, err)
	}
	replacement := managerConfig(t, first.Tag, 9443)
	if _, err := manager.ApplyControllerDesiredWithResult(ctx, replacement, replacement.Digest, state5); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("same-revision structural change error = %v", err)
	}
	if _, err := manager.ApplyControllerDesiredWithResult(ctx, first, first.Digest, managerControllerState("catalog-owned", 4, "clients-a")); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("stale apply error = %v", err)
	}
	if err := manager.ApplyDesired(ctx, replacement, replacement.Digest); !errors.Is(err, ErrControllerOwned) {
		t.Fatalf("legacy replace error = %v", err)
	}
	if err := manager.Remove(ctx, first.Tag); !errors.Is(err, ErrControllerOwned) {
		t.Fatalf("legacy delete error = %v", err)
	}
	if err := manager.RemoveControllerDesired(ctx, first.Tag, "catalog-owned", 4); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("stale tombstone error = %v", err)
	}
	if err := manager.RemoveControllerDesired(ctx, first.Tag, "catalog-owned", 5); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("same-revision tombstone error = %v", err)
	}
	if _, exists := core.inbounds[first.Tag]; !exists {
		t.Fatal("rejected tombstone changed runtime")
	}
	if err := manager.RemoveControllerDesired(ctx, first.Tag, "catalog-owned", 6); err != nil {
		t.Fatal(err)
	}
	if _, exists := core.inbounds[first.Tag]; exists {
		t.Fatal("new tombstone left runtime inbound")
	}
	if _, err := manager.ApplyControllerDesiredWithResult(ctx, first, first.Digest, state5); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("stale resurrection error = %v", err)
	}
	if _, err := manager.ApplyControllerDesiredWithResult(ctx, first, first.Digest, managerControllerState("other-owner", 7, "clients-a")); !errors.Is(err, ErrControllerOwnership) {
		t.Fatalf("tag takeover error = %v", err)
	}
	if _, err := manager.ApplyControllerDesiredWithResult(ctx, first, first.Digest, managerControllerState("catalog-owned", 7, "clients-a")); err != nil {
		t.Fatalf("newer reactivation failed: %v", err)
	}
}
