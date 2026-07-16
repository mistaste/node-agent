package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/guardex/node-agent/internal/inbound"
)

const emptySetSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func testControllerState(id string, revision int64) InboundControllerState {
	return InboundControllerState{
		InboundID:              id,
		DesiredRevision:        revision,
		AppliedRevision:        revision,
		Status:                 "active",
		PublicMaterialJSON:     json.RawMessage(`{"public_key":"public-only"}`),
		ClientParamsJSON:       json.RawMessage(`{}`),
		AppliedClientSetSHA256: emptySetSHA256,
	}
}

func testInbound(t *testing.T, tag string, port int) inbound.Config {
	t.Helper()
	raw := strings.ReplaceAll(`{
		"tag":"TAG","port":443,"protocol":"vless",
		"settings":{"clients":[],"decryption":"none"},
		"streamSettings":{"network":"tcp","security":"reality","realitySettings":{
			"dest":"www.example.com:443","serverNames":["www.example.com"],
			"privateKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortIds":["0123456789abcdef"]
		}}
	}`, "TAG", tag)
	raw = strings.Replace(raw, `"port":443`, `"port":`+strconv.Itoa(port), 1)
	cfg, err := inbound.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func testHysteriaInbound(t *testing.T, tag string, port int) inbound.Config {
	t.Helper()
	certificateFile, keyFile := inbound.ManagedTLSPaths(tag)
	raw := fmt.Sprintf(`{
		"tag":%q,"port":%d,"protocol":"hysteria",
		"settings":{"version":2,"clients":[]},
		"streamSettings":{"network":"hysteria","security":"tls",
			"tlsSettings":{"serverName":"203.0.113.10","alpn":["h3"],"minVersion":"1.3","maxVersion":"1.3","certificates":[{"certificateFile":%q,"keyFile":%q}]},
			"hysteriaSettings":{"version":2,"auth":"","udpIdleTimeout":60,"masquerade":{}},
			"finalmask":{"udp":[{"type":"salamander","settings":{"password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}]}
		}
	}`, tag, port, certificateFile, keyFile)
	cfg, err := inbound.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestInboundStoreRoundTripAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "inbounds.json")
	store := NewInboundStore(path)
	cfg := testInbound(t, "dynamic-1", 8443)
	changed, err := store.Put(cfg)
	if err != nil || !changed {
		t.Fatalf("Put changed=%v err=%v", changed, err)
	}
	changed, err = store.Put(cfg)
	if err != nil || changed {
		t.Fatalf("idempotent Put changed=%v err=%v", changed, err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("store permissions = %o, want 600", got)
	}
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(disk), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") {
		t.Fatal("durable config lost required server key")
	}

	reloaded := NewInboundStore(path)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	records := reloaded.All()
	if len(records) != 1 || records[0].Config.Digest != cfg.Digest || records[0].Config.Tag != cfg.Tag {
		t.Fatalf("reloaded records = %+v", records)
	}
}

func TestInboundStoreRemoveAndReplaceAllOnlyAffectDynamicInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbounds.json")
	store := NewInboundStore(path)
	a := testInbound(t, "dynamic-a", 8443)
	b := testInbound(t, "dynamic-b", 9443)
	if _, err := store.Put(a); err != nil {
		t.Fatal(err)
	}
	removed, err := store.Remove("vless-in")
	if err != nil || removed {
		t.Fatalf("static inbound removal changed=%v err=%v", removed, err)
	}
	if err := store.ReplaceAll([]inbound.Config{b}); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get("dynamic-a"); ok {
		t.Fatal("old dynamic inbound remained after manifest replacement")
	}
	if record, ok := store.Get("dynamic-b"); !ok || record.Config.Digest != b.Digest {
		t.Fatalf("replacement record = %+v, ok=%v", record, ok)
	}
}

func TestInboundStoreRejectsCorruptOrUnsafeDiskState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbounds.json")
	unsafe := `{"version":1,"inbounds":[{"config":{"tag":"bad","port":53,"protocol":"shadowsocks","settings":{},"streamSettings":{"network":"tcp","security":"tls"}},"updated_at":"2026-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(path, []byte(unsafe), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := NewInboundStore(path).Load(); err == nil {
		t.Fatal("Load accepted unsafe persisted protocol")
	}
}

func TestInboundStoreRollsBackMemoryWhenAtomicWriteFails(t *testing.T) {
	store := NewInboundStore("")
	cfg := testInbound(t, "not-persisted", 8443)
	if _, err := store.Put(cfg); err == nil {
		t.Fatal("Put with empty path unexpectedly succeeded")
	}
	if len(store.All()) != 0 {
		t.Fatal("failed durable write remained in memory")
	}
}

func TestInboundStoreMigratesV1AndPersistsControllerObservedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbounds.json")
	cfg := testInbound(t, "gx-migrated", 8443)
	v1 := inboundDiskStore{
		Version:  1,
		Inbounds: []inboundDiskRecord{{Config: cfg.Raw, DesiredDigest: cfg.Digest}},
	}
	raw, err := json.Marshal(v1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	inventory := NewInboundStore(path)
	if err := inventory.Load(); err != nil {
		t.Fatal(err)
	}
	if record, ok := inventory.Get(cfg.Tag); !ok || record.Config.Digest != cfg.Digest || record.Controller.InboundID != "" {
		t.Fatalf("v1 record migration = %+v, ok=%v", record, ok)
	}
	controller := InboundControllerState{
		InboundID:              "catalog-id",
		DesiredRevision:        4,
		AppliedRevision:        4,
		Status:                 "active",
		PublicMaterialJSON:     json.RawMessage(`{"public_key":"public-only"}`),
		ClientParamsJSON:       json.RawMessage(`{"path":"/sync"}`),
		ClientSecretJSON:       json.RawMessage(`{"salamander_password":"node-secret"}`),
		AppliedClientSetSHA256: emptySetSHA256,
		AppliedClientCount:     0,
	}
	if _, err := inventory.PutControllerDesired(cfg, cfg.Digest, controller); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var disk inboundDiskStore
	if err := json.Unmarshal(saved, &disk); err != nil {
		t.Fatal(err)
	}
	if disk.Version != inboundStoreVersion {
		t.Fatalf("saved version = %d, want %d", disk.Version, inboundStoreVersion)
	}
	reloaded := NewInboundStore(path)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	record, ok := reloaded.Get(cfg.Tag)
	var clientSecret map[string]string
	_ = json.Unmarshal(record.Controller.ClientSecretJSON, &clientSecret)
	if !ok || record.Controller.InboundID != "catalog-id" || record.Controller.AppliedRevision != 4 || record.Controller.Status != "active" || record.Config.Digest != cfg.Digest || clientSecret["salamander_password"] != "node-secret" {
		t.Fatalf("migrated controller record = %+v, ok=%v", record, ok)
	}
}

func TestV3LegacyRollbackAfterHysteriaTombstoneIgnoresClientSecretField(t *testing.T) {
	t.Setenv("HYSTERIA_TLS_DIR", filepath.Join(t.TempDir(), "tls"))
	path := filepath.Join(t.TempDir(), "inbounds.json")
	inventory := NewInboundStore(path)
	vless := testInbound(t, "gx-legacy-vless", 8443)
	vlessState := testControllerState("catalog-vless", 1)
	vlessState.ClientSecretJSON = json.RawMessage(`{"future_optional_field":"ignored-by-v0.2.3"}`)
	if _, err := inventory.PutControllerDesired(vless, vless.Digest, vlessState); err != nil {
		t.Fatal(err)
	}
	hysteria := testHysteriaInbound(t, "gx-legacy-hysteria", 24443)
	hysteriaState := testControllerState("catalog-hysteria", 1)
	hysteriaState.ClientSecretJSON = json.RawMessage(`{"salamander_password":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	if _, err := inventory.PutControllerDesired(hysteria, hysteria.Digest, hysteriaState); err != nil {
		t.Fatal(err)
	}
	if err := CheckLegacyV3Rollback(path); err == nil || !strings.Contains(err.Error(), "delete/tombstone") {
		t.Fatalf("rollback check accepted active Hysteria record: %v", err)
	}
	if err := inventory.PutControllerTombstone(hysteria.Tag, "catalog-hysteria", 2); err != nil {
		t.Fatal(err)
	}
	if err := CheckLegacyV3Rollback(path); err != nil {
		t.Fatalf("rollback check rejected tombstoned Hysteria store: %v", err)
	}

	// Model the exact fields known by the already-released v0.2.3 reader. Go's
	// JSON decoder ignores client_secret_json, while the active configs now only
	// contain VLESS and therefore pass its protocol gate.
	type legacyRecord struct {
		Config       json.RawMessage `json:"config"`
		InboundID    string          `json:"inbound_id,omitempty"`
		ClientParams json.RawMessage `json:"client_params_json,omitempty"`
	}
	type legacyStore struct {
		Version    int                              `json:"version"`
		Inbounds   []legacyRecord                   `json:"inbounds"`
		Tombstones []inboundControllerTombstoneDisk `json:"controller_tombstones,omitempty"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "client_secret_json") {
		t.Fatal("test store did not contain the additive secret field")
	}
	var legacy legacyStore
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatalf("v0.2.3-shaped reader rejected additive field: %v", err)
	}
	if legacy.Version != 3 || len(legacy.Inbounds) != 1 || len(legacy.Tombstones) != 1 {
		t.Fatalf("legacy rollback view = %+v", legacy)
	}
	var identity struct {
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal(legacy.Inbounds[0].Config, &identity); err != nil || identity.Protocol != "vless" {
		t.Fatalf("legacy active config protocol=%q err=%v", identity.Protocol, err)
	}
}

func TestControllerTombstonePersistsMonotonicHighWaterAndOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbounds.json")
	inventory := NewInboundStore(path)
	cfg := testInbound(t, "gx-revision-ledger", 8443)
	if _, err := inventory.PutControllerDesired(cfg, cfg.Digest, testControllerState("catalog-ledger", 5)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := inventory.ControllerDeleteState(cfg.Tag, "catalog-ledger", 4); !errors.Is(err, ErrControllerStaleRevision) {
		t.Fatalf("stale tombstone error = %v", err)
	}
	if _, _, err := inventory.ControllerDeleteState(cfg.Tag, "catalog-ledger", 5); !errors.Is(err, ErrControllerRevisionConflict) {
		t.Fatalf("same-revision action change error = %v", err)
	}
	removeRuntime, idempotent, err := inventory.ControllerDeleteState(cfg.Tag, "catalog-ledger", 6)
	if err != nil || !removeRuntime || idempotent {
		t.Fatalf("new tombstone preflight remove=%v idempotent=%v err=%v", removeRuntime, idempotent, err)
	}
	if err := inventory.PutControllerTombstone(cfg.Tag, "catalog-ledger", 6); err != nil {
		t.Fatal(err)
	}
	if _, ok := inventory.Get(cfg.Tag); ok {
		t.Fatal("active record remained after tombstone")
	}

	reloaded := NewInboundStore(path)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	tombstone, ok := reloaded.ControllerTombstone(cfg.Tag)
	if !ok || tombstone.InboundID != "catalog-ledger" || tombstone.DesiredRevision != 6 {
		t.Fatalf("reloaded tombstone = %+v, ok=%v", tombstone, ok)
	}
	if _, err := reloaded.PutControllerDesired(cfg, cfg.Digest, testControllerState("catalog-ledger", 5)); !errors.Is(err, ErrControllerStaleRevision) {
		t.Fatalf("stale resurrection error = %v", err)
	}
	if _, err := reloaded.PutControllerDesired(cfg, cfg.Digest, testControllerState("catalog-ledger", 6)); !errors.Is(err, ErrControllerRevisionConflict) {
		t.Fatalf("same-revision resurrection error = %v", err)
	}
	if _, err := reloaded.PutControllerDesired(cfg, cfg.Digest, testControllerState("other-owner", 7)); !errors.Is(err, ErrControllerOwnership) {
		t.Fatalf("tag takeover error = %v", err)
	}
	if _, err := reloaded.PutDesired(cfg, cfg.Digest); !errors.Is(err, ErrControllerOwned) {
		t.Fatalf("manual resurrection error = %v", err)
	}
	if _, err := reloaded.PutControllerDesired(cfg, cfg.Digest, testControllerState("catalog-ledger", 7)); err != nil {
		t.Fatalf("newer reactivation failed: %v", err)
	}
	if _, ok := reloaded.ControllerTombstone(cfg.Tag); ok {
		t.Fatal("tombstone remained after a newer apply")
	}
}

func TestControllerStateUpdateUsesRevisionCAS(t *testing.T) {
	inventory := NewInboundStore(filepath.Join(t.TempDir(), "inbounds.json"))
	cfg := testInbound(t, "gx-state-cas", 8443)
	state := testControllerState("catalog-state", 8)
	if _, err := inventory.PutControllerDesired(cfg, cfg.Digest, state); err != nil {
		t.Fatal(err)
	}
	stale := state
	stale.DesiredRevision = 7
	stale.AppliedRevision = 7
	if err := inventory.UpdateControllerState(cfg.Tag, stale); !errors.Is(err, ErrControllerStaleRevision) {
		t.Fatalf("stale observed update error = %v", err)
	}
	stored, _ := inventory.Get(cfg.Tag)
	if stored.Controller.DesiredRevision != 8 {
		t.Fatalf("stale update changed durable state: %+v", stored.Controller)
	}
}
