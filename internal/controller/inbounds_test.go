package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardex/node-agent/internal/config"
	"github.com/guardex/node-agent/internal/inbound"
	"github.com/guardex/node-agent/internal/inboundsync"
	"github.com/guardex/node-agent/internal/store"
	"github.com/guardex/node-agent/internal/userops"
	"github.com/guardex/node-agent/internal/xray"
)

const testClientUUID = "6f8d0c5b-6c62-4b35-9231-b2af180b5284"

type controllerFakeCore struct {
	mu              sync.Mutex
	inbounds        map[string][]byte
	users           map[string]map[string]string
	addInboundCalls int
	addUserCalls    int
	removeUserCalls int
	failNextAddUser bool
}

func newControllerFakeCore() *controllerFakeCore {
	return &controllerFakeCore{inbounds: make(map[string][]byte), users: make(map[string]map[string]string)}
}

func (f *controllerFakeCore) AddInboundFromJSON(_ context.Context, raw []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cfg, err := inbound.Parse(raw)
	if err != nil {
		return err
	}
	if _, exists := f.inbounds[cfg.Tag]; exists {
		return errors.New("existing tag found: " + cfg.Tag)
	}
	f.inbounds[cfg.Tag] = append([]byte(nil), raw...)
	f.users[cfg.Tag] = make(map[string]string)
	f.addInboundCalls++
	return nil
}

func (f *controllerFakeCore) RemoveInbound(_ context.Context, tag string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.inbounds[tag]; !exists {
		return errors.New("not enough information for making a decision")
	}
	delete(f.inbounds, tag)
	delete(f.users, tag)
	return nil
}

func (f *controllerFakeCore) AddUser(_ context.Context, params xray.AddUserParams) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addUserCalls++
	if f.failNextAddUser {
		f.failNextAddUser = false
		return errors.New("temporary AlterInbound failure")
	}
	users, exists := f.users[params.InboundTag]
	if !exists {
		return errors.New("inbound not found")
	}
	if _, exists := users[params.UUID]; exists {
		return errors.New("already exists")
	}
	users[params.UUID] = params.Flow
	return nil
}

func (f *controllerFakeCore) RemoveUser(_ context.Context, tag, uuid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removeUserCalls++
	users, exists := f.users[tag]
	if !exists {
		return errors.New("inbound not found")
	}
	if _, exists := users[uuid]; !exists {
		return errors.New("not enough information for making a decision")
	}
	delete(users, uuid)
	return nil
}

func (f *controllerFakeCore) ListInboundUserIDs(_ context.Context, tag string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	users, exists := f.users[tag]
	if !exists {
		return nil, errors.New("inbound not found")
	}
	ids := make([]string, 0, len(users))
	for uuid := range users {
		ids = append(ids, uuid)
	}
	return ids, nil
}

func (f *controllerFakeCore) ListInboundTags(_ context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tags := make([]string, 0, len(f.inbounds))
	for tag := range f.inbounds {
		tags = append(tags, tag)
	}
	return tags, nil
}

func (f *controllerFakeCore) raw(tag string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.inbounds[tag]...)
}

func applyItem(id, tag string, port int, revision int64, clients ...string) desiredItem {
	if !strings.HasPrefix(tag, "gx-") {
		tag = "gx-" + tag
	}
	configJSON := json.RawMessage(`{
		"tag":"ignored-by-controller","port":9999,"protocol":"vless",
		"settings":{"clients":[{"id":"00000000-0000-4000-8000-000000000000"}],"decryption":"none"},
		"streamSettings":{"network":"xhttp","security":"reality","realitySettings":{
			"dest":"www.example.com:443","serverNames":["www.example.com"]
		},"xhttpSettings":{"path":"/assets/sync"}}
	}`)
	return desiredItem{
		InboundID:       id,
		Action:          "apply",
		DesiredRevision: revision,
		EffectiveTag:    tag,
		EffectivePort:   port,
		ConfigJSON:      configJSON,
		ClientUUIDs:     clients,
	}
}

type controllerHarness struct {
	t            *testing.T
	server       *httptest.Server
	reconciler   *Reconciler
	manager      *inboundsync.Manager
	inventory    *store.InboundStore
	userStore    *store.Store
	core         *controllerFakeCore
	mu           sync.Mutex
	items        []desiredItem
	serverID     string
	reports      []observedReport
	getCalls     int
	invalidJSON  bool
	desiredHook  func()
	reportSignal chan struct{}
}

func newControllerHarness(t *testing.T, items []desiredItem, coordinators ...*userops.Coordinator) *controllerHarness {
	t.Helper()
	h := &controllerHarness{t: t, items: items, serverID: "server-test", core: newControllerFakeCore(), reportSignal: make(chan struct{}, 16)}
	h.inventory = store.NewInboundStore(filepath.Join(t.TempDir(), "inbounds.json"))
	h.userStore = store.New(filepath.Join(t.TempDir(), "users.json"))
	h.manager = inboundsync.New(h.core, h.inventory, time.Minute, "vless-in", "api")
	h.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Service-Token") != "service-token" || r.Header.Get("X-Node-Secret") != "node-secret" {
			t.Errorf("missing controller authentication headers")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/internal/node/inbounds":
			h.mu.Lock()
			h.getCalls++
			items := append([]desiredItem(nil), h.items...)
			serverID := h.serverID
			invalidJSON := h.invalidJSON
			desiredHook := h.desiredHook
			h.mu.Unlock()
			if desiredHook != nil {
				desiredHook()
			}
			if invalidJSON {
				_, _ = w.Write([]byte(`{"items":`))
				return
			}
			_ = json.NewEncoder(w).Encode(desiredResponse{ServerID: serverID, GeneratedAt: time.Now().UTC(), Items: items})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/internal/node/inbounds/report":
			var report observedReport
			if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
				t.Errorf("decode report: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			h.mu.Lock()
			h.reports = append(h.reports, report)
			h.mu.Unlock()
			select {
			case h.reportSignal <- struct{}{}:
			default:
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(h.server.Close)
	cfg := &config.Config{
		ControllerURL:        h.server.URL,
		InternalServiceToken: "service-token",
		Secret:               "node-secret",
		Version:              "test-agent",
		XrayCoreVersion:      "26.6.1",
		ResyncInterval:       20 * time.Millisecond,
	}
	reconciler, err := New(cfg, h.manager, h.userStore, h.core, coordinators...)
	if err != nil {
		t.Fatal(err)
	}
	reconciler.http = h.server.Client()
	reconciler.http.Timeout = requestTimeout
	reconciler.http.CheckRedirect = rejectRedirect
	h.reconciler = reconciler
	return h
}

func (h *controllerHarness) setItems(items []desiredItem) {
	h.mu.Lock()
	h.items = append([]desiredItem(nil), items...)
	h.mu.Unlock()
}

func (h *controllerHarness) setInvalidJSON(invalid bool) {
	h.mu.Lock()
	h.invalidJSON = invalid
	h.mu.Unlock()
}

func (h *controllerHarness) latestReport() observedReport {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.reports) == 0 {
		h.t.Fatal("controller did not submit a report")
	}
	return h.reports[len(h.reports)-1]
}

func TestControllerPullAppliesExactClientsPersistsStateAndReportsPublicMaterial(t *testing.T) {
	item := applyItem("catalog-1", "vless-adaptive", 2053, 7, testClientUUID)
	h := newControllerHarness(t, []desiredItem{item})
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	record, ok := h.inventory.Get(item.EffectiveTag)
	if !ok {
		t.Fatal("controller desired inbound was not persisted")
	}
	if record.Controller.InboundID != item.InboundID || record.Controller.DesiredRevision != 7 || record.Controller.AppliedRevision != 7 || record.Controller.Status != "active" {
		t.Fatalf("durable controller state = %+v", record.Controller)
	}
	if record.Controller.AppliedClientCount != 1 || record.Controller.AppliedClientSetSHA256 == "" {
		t.Fatalf("durable client state = %+v", record.Controller)
	}
	if !strings.Contains(string(record.Config.Raw), `"privateKey"`) {
		t.Fatal("node runtime config did not retain its per-node Reality key")
	}
	var runtime struct {
		Tag      string `json:"tag"`
		Port     int    `json:"port"`
		Settings struct {
			Clients []struct {
				ID string `json:"id"`
			} `json:"clients"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(h.core.raw(item.EffectiveTag), &runtime); err != nil {
		t.Fatal(err)
	}
	if runtime.Tag != item.EffectiveTag || runtime.Port != item.EffectivePort || len(runtime.Settings.Clients) != 0 {
		t.Fatalf("runtime config identity/clients = %+v", runtime)
	}
	h.core.mu.Lock()
	runtimeFlow, runtimeUserExists := h.core.users[item.EffectiveTag][testClientUUID]
	h.core.mu.Unlock()
	if !runtimeUserExists || runtimeFlow != "" {
		t.Fatalf("runtime AlterInbound user missing: exists=%v flow=%q", runtimeUserExists, runtimeFlow)
	}

	report := h.latestReport()
	if len(report.Deployments) != 1 {
		t.Fatalf("deployments = %+v", report.Deployments)
	}
	deployment := report.Deployments[0]
	if deployment.Status != "active" || deployment.AppliedRevision != 7 || deployment.AppliedClientCount != 1 || deployment.AppliedClientSetSHA256 == "" {
		t.Fatalf("deployment report = %+v", deployment)
	}
	if !bytesContainsJSONKey(deployment.PublicMaterialJSON, "public_key") || !bytesContainsJSONKey(deployment.PublicMaterialJSON, "short_id") {
		t.Fatalf("public Reality material missing: %s", deployment.PublicMaterialJSON)
	}
	reportJSON, _ := json.Marshal(report)
	if strings.Contains(string(reportJSON), "privateKey") || strings.Contains(string(reportJSON), "node-secret") || strings.Contains(string(reportJSON), "service-token") {
		t.Fatalf("report leaked secret material: %s", reportJSON)
	}
	if !strings.Contains(string(report.Capabilities.RawJSON), `"controller_polling":true`) {
		t.Fatalf("capabilities = %s", report.Capabilities.RawJSON)
	}

	firstPublic := string(deployment.PublicMaterialJSON)
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if secondPublic := string(h.latestReport().Deployments[0].PublicMaterialJSON); secondPublic != firstPublic {
		t.Fatalf("Reality public material rotated on idempotent retry: %s != %s", firstPublic, secondPublic)
	}
}

func TestClientOnlyManifestChangeDoesNotRecreateStructuralInbound(t *testing.T) {
	firstUUID := testClientUUID
	secondUUID := "58b0a900-c7c2-4bf0-91ca-2da9c781b18d"
	item := applyItem("catalog-users", "vless-users", 2053, 3, firstUUID)
	h := newControllerHarness(t, []desiredItem{item})
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.core.mu.Lock()
	initialStructuralAdds := h.core.addInboundCalls
	h.core.mu.Unlock()

	item.ClientUUIDs = []string{secondUUID}
	h.setItems([]desiredItem{item})
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.core.mu.Lock()
	defer h.core.mu.Unlock()
	if h.core.addInboundCalls != initialStructuralAdds {
		t.Fatalf("client-only change recreated inbound: adds %d -> %d", initialStructuralAdds, h.core.addInboundCalls)
	}
	if _, exists := h.core.users[item.EffectiveTag][firstUUID]; exists {
		t.Fatal("removed client remained in runtime")
	}
	if _, exists := h.core.users[item.EffectiveTag][secondUUID]; !exists {
		t.Fatal("new client was not added to runtime")
	}
	if h.core.addUserCalls < 2 || h.core.removeUserCalls < 1 {
		t.Fatalf("user reconciliation calls add=%d remove=%d", h.core.addUserCalls, h.core.removeUserCalls)
	}
}

func TestControllerRecreatesRuntimeUserWhenDurableFlowObservationIsMissing(t *testing.T) {
	item := applyItem("catalog-runtime-flow", "runtime-flow", 2053, 3, testClientUUID)
	h := newControllerHarness(t, []desiredItem{item})
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.userStore.Remove(item.EffectiveTag, testClientUUID); err != nil {
		t.Fatal(err)
	}
	h.core.mu.Lock()
	removesBefore := h.core.removeUserCalls
	addsBefore := h.core.addUserCalls
	h.core.mu.Unlock()

	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.core.mu.Lock()
	defer h.core.mu.Unlock()
	if h.core.removeUserCalls != removesBefore+1 || h.core.addUserCalls != addsBefore+1 {
		t.Fatalf("unknown runtime flow was trusted: add %d -> %d, remove %d -> %d", addsBefore, h.core.addUserCalls, removesBefore, h.core.removeUserCalls)
	}
	if _, ok := h.core.users[item.EffectiveTag][testClientUUID]; !ok {
		t.Fatal("desired runtime user was not restored")
	}
}

func TestControllerRemovesUnexpectedNonUUIDRuntimeLabel(t *testing.T) {
	item := applyItem("catalog-runtime-extra", "runtime-extra", 2053, 3, testClientUUID)
	h := newControllerHarness(t, []desiredItem{item})
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.core.mu.Lock()
	h.core.users[item.EffectiveTag]["legacy-client-label"] = ""
	h.core.mu.Unlock()

	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.core.mu.Lock()
	defer h.core.mu.Unlock()
	if _, exists := h.core.users[item.EffectiveTag]["legacy-client-label"]; exists {
		t.Fatal("unexpected runtime label survived exact client reconciliation")
	}
	if _, exists := h.core.users[item.EffectiveTag][testClientUUID]; !exists {
		t.Fatal("desired runtime user was removed with the unexpected label")
	}
}

func TestIncompleteClientReconcileRetriesWithoutStructuralReapply(t *testing.T) {
	item := applyItem("catalog-client-retry", "vless-client-retry", 2053, 4, testClientUUID)
	h := newControllerHarness(t, []desiredItem{item})
	h.core.mu.Lock()
	h.core.failNextAddUser = true
	h.core.mu.Unlock()

	if err := h.reconciler.SyncOnce(context.Background()); err == nil {
		t.Fatal("partial client reconciliation unexpectedly succeeded")
	}
	first := h.latestReport().Deployments[0]
	if first.Status != "degraded" || first.ErrorCode != "client_reconcile_incomplete" {
		t.Fatalf("first report = %+v", first)
	}
	h.core.mu.Lock()
	structuralAdds := h.core.addInboundCalls
	h.core.mu.Unlock()

	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := h.latestReport().Deployments[0]
	if second.Status != "active" || second.AppliedClientCount != 1 {
		t.Fatalf("second report = %+v", second)
	}
	h.core.mu.Lock()
	defer h.core.mu.Unlock()
	if h.core.addInboundCalls != structuralAdds {
		t.Fatalf("client retry recreated structural inbound: adds %d -> %d", structuralAdds, h.core.addInboundCalls)
	}
	if _, ok := h.core.users[item.EffectiveTag][testClientUUID]; !ok {
		t.Fatal("client retry did not converge runtime membership")
	}
}

func TestControllerRejectsWholeManifestBeforeMutation(t *testing.T) {
	first := applyItem("catalog-1", "vless-one", 2053, 1, testClientUUID)
	h := newControllerHarness(t, []desiredItem{first})
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := h.core.raw(first.EffectiveTag)

	replacement := applyItem("catalog-1", "vless-one", 2083, 2, testClientUUID)
	conflict := applyItem("catalog-2", "vless-two", 2083, 1, testClientUUID)
	h.setItems([]desiredItem{replacement, conflict})
	if err := h.reconciler.SyncOnce(context.Background()); err == nil {
		t.Fatal("duplicate port manifest unexpectedly succeeded")
	}
	if after := h.core.raw(first.EffectiveTag); string(after) != string(before) {
		t.Fatal("last-known-good runtime changed after whole-manifest validation failure")
	}
	if _, ok := h.inventory.Get("vless-two"); ok {
		t.Fatal("invalid manifest partially persisted another item")
	}
	report := h.latestReport()
	if len(report.Deployments) != 2 || report.Deployments[0].Status != "degraded" || report.Deployments[0].AppliedRevision != 1 || !bytesContainsJSONKey(report.Deployments[0].PublicMaterialJSON, "public_key") || report.Deployments[1].Status != "failed" {
		t.Fatalf("invalid manifest report = %+v", report.Deployments)
	}
}

func TestWholeManifestRejectionReportsUnaffectedLastKnownGoodAsActive(t *testing.T) {
	active := applyItem("catalog-lkg", "vless-lkg", 2053, 4, testClientUUID)
	h := newControllerHarness(t, []desiredItem{active})
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := h.latestReport().Deployments[0]
	if first.Status != "active" || first.AppliedRevision != active.DesiredRevision {
		t.Fatalf("initial deployment = %+v", first)
	}

	invalid := applyItem("catalog-invalid-collateral", "invalid-collateral", 2083, 1)
	invalid.Action = "rotate"
	h.setItems([]desiredItem{active, invalid})
	if err := h.reconciler.SyncOnce(context.Background()); err == nil {
		t.Fatal("invalid collateral manifest unexpectedly succeeded")
	}
	report := h.latestReport()
	if len(report.Deployments) != 2 {
		t.Fatalf("deployments = %+v", report.Deployments)
	}
	lkg := report.Deployments[0]
	if lkg.Status != "active" || lkg.AppliedRevision != active.DesiredRevision || lkg.ErrorCode != "" || lkg.ErrorMessage != "" {
		t.Fatalf("unaffected last-known-good deployment was erased or degraded: %+v", lkg)
	}
	if !bytesContainsJSONKey(lkg.PublicMaterialJSON, "public_key") || !bytesContainsJSONKey(lkg.PublicMaterialJSON, "short_id") {
		t.Fatalf("unaffected last-known-good public material was erased: %s", lkg.PublicMaterialJSON)
	}
	if report.Deployments[1].Status != "failed" || report.Deployments[1].ErrorCode != "unsupported_action" {
		t.Fatalf("invalid deployment = %+v", report.Deployments[1])
	}
}

func TestStaleInvalidManifestCannotDegradeNewerLastKnownGood(t *testing.T) {
	active := applyItem("catalog-stale-invalid", "stale-invalid", 2053, 5, testClientUUID)
	h := newControllerHarness(t, []desiredItem{active})
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	stale := active
	stale.DesiredRevision = 4
	stale.Action = "rotate"
	h.setItems([]desiredItem{stale})
	if err := h.reconciler.SyncOnce(context.Background()); err == nil {
		t.Fatal("stale invalid manifest unexpectedly passed validation")
	}
	report := h.latestReport().Deployments[0]
	if report.Status != "active" || report.AppliedRevision != 5 || report.ErrorCode != "" || report.ErrorMessage != "" {
		t.Fatalf("stale invalid desired state degraded newer last-known-good: %+v", report)
	}
	if !bytesContainsJSONKey(report.PublicMaterialJSON, "public_key") {
		t.Fatalf("stale invalid desired state erased public material: %s", report.PublicMaterialJSON)
	}
}

func TestInvalidJSONPreservesLastKnownGoodWithoutReportingMutation(t *testing.T) {
	item := applyItem("catalog-json", "vless-json", 2053, 1, testClientUUID)
	item.Code = "adaptive-xhttp"
	h := newControllerHarness(t, []desiredItem{item})
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := h.core.raw(item.EffectiveTag)
	h.mu.Lock()
	reportsBefore := len(h.reports)
	h.mu.Unlock()
	h.setInvalidJSON(true)

	if err := h.reconciler.SyncOnce(context.Background()); err == nil {
		t.Fatal("invalid JSON unexpectedly succeeded")
	}
	if after := h.core.raw(item.EffectiveTag); string(after) != string(before) {
		t.Fatal("invalid fetch changed last-known-good runtime")
	}
	h.mu.Lock()
	reportsAfter := len(h.reports)
	h.mu.Unlock()
	if reportsAfter != reportsBefore {
		t.Fatalf("invalid fetch submitted an observed mutation report: %d -> %d", reportsBefore, reportsAfter)
	}
}

func TestControllerTombstoneRequiresMatchingOwnershipAndProtectsBaseline(t *testing.T) {
	item := applyItem("catalog-1", "vless-delete-me", 2053, 1, testClientUUID)
	h := newControllerHarness(t, []desiredItem{item})
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	wrongOwner := desiredItem{InboundID: "catalog-other", Action: "delete", DesiredRevision: 2, EffectiveTag: item.EffectiveTag, EffectivePort: item.EffectivePort}
	h.setItems([]desiredItem{wrongOwner})
	if err := h.reconciler.SyncOnce(context.Background()); err == nil {
		t.Fatal("wrong-owner tombstone unexpectedly succeeded")
	}
	if _, ok := h.inventory.Get(item.EffectiveTag); !ok {
		t.Fatal("wrong-owner tombstone removed durable inbound")
	}

	correct := desiredItem{InboundID: item.InboundID, Action: "delete", DesiredRevision: 2, EffectiveTag: item.EffectiveTag, EffectivePort: item.EffectivePort}
	h.setItems([]desiredItem{correct})
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.inventory.Get(item.EffectiveTag); ok || len(h.core.raw(item.EffectiveTag)) != 0 {
		t.Fatal("matching tombstone did not remove managed inbound")
	}
	if got := h.latestReport().Deployments[0].Status; got != "deleted" {
		t.Fatalf("tombstone status = %q", got)
	}

	h.core.mu.Lock()
	h.core.inbounds["vless-in"] = []byte("static")
	h.core.mu.Unlock()
	protected := desiredItem{InboundID: "baseline", Action: "delete", DesiredRevision: 1, EffectiveTag: "vless-in", EffectivePort: 443}
	h.setItems([]desiredItem{protected})
	if err := h.reconciler.SyncOnce(context.Background()); err == nil {
		t.Fatal("protected baseline tombstone unexpectedly succeeded")
	}
	if len(h.core.raw("vless-in")) == 0 {
		t.Fatal("protected baseline was removed")
	}
}

func TestControllerRunRetriesAfterOfflineFetch(t *testing.T) {
	item := applyItem("catalog-retry", "vless-retry", 2053, 1, testClientUUID)
	h := newControllerHarness(t, []desiredItem{item})
	baseClient := h.reconciler.http
	var requests int
	h.reconciler.http = &http.Client{
		Timeout: requestTimeout,
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method == http.MethodGet {
				requests++
				if requests == 1 {
					return nil, errors.New("temporary offline")
				}
			}
			return baseClient.Transport.RoundTrip(req)
		}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.reconciler.Run(ctx)
	select {
	case <-h.reportSignal:
	case <-time.After(2 * time.Second):
		t.Fatal("controller did not retry after offline fetch")
	}
	if requests < 2 {
		t.Fatalf("GET requests = %d, want retry", requests)
	}
	if _, ok := h.inventory.Get(item.EffectiveTag); !ok {
		t.Fatal("retry did not apply desired inbound")
	}
}

func TestControllerRejectsServerOwnedRealityMaterialBeforeMutation(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		key   string
		value any
	}{
		{name: "private key", key: "privateKey", value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{name: "short ids", key: "shortIds", value: []string{"0123456789abcdef"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			item := applyItem("catalog-node-key", "node-key", 2053, 1, testClientUUID)
			var root map[string]any
			if err := json.Unmarshal(item.ConfigJSON, &root); err != nil {
				t.Fatal(err)
			}
			stream := root["streamSettings"].(map[string]any)
			reality := stream["realitySettings"].(map[string]any)
			reality[testCase.key] = testCase.value
			item.ConfigJSON, _ = json.Marshal(root)
			h := newControllerHarness(t, []desiredItem{item})
			if err := h.reconciler.SyncOnce(context.Background()); err == nil {
				t.Fatal("controller accepted server-owned Reality material")
			}
			if len(h.inventory.All()) != 0 || len(h.core.raw(item.EffectiveTag)) != 0 {
				t.Fatal("rejected Reality material mutated durable or runtime state")
			}
			deployment := h.latestReport().Deployments[0]
			if deployment.Status != "failed" || deployment.ErrorCode != "invalid_desired_config" {
				t.Fatalf("rejection report = %+v", deployment)
			}
		})
	}
}

func TestControllerRevisionAndTombstoneHighWaterNeverRegressesRuntime(t *testing.T) {
	item := applyItem("catalog-revision", "revision", 2053, 5, testClientUUID)
	h := newControllerHarness(t, []desiredItem{item})
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	original := h.core.raw(item.EffectiveTag)

	staleApply := applyItem(item.InboundID, item.EffectiveTag, 2083, 4, testClientUUID)
	h.setItems([]desiredItem{staleApply})
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatalf("stale apply should be an idempotent LKG observation: %v", err)
	}
	if after := h.core.raw(item.EffectiveTag); string(after) != string(original) {
		t.Fatal("stale apply changed runtime")
	}
	if report := h.latestReport().Deployments[0]; report.Status != "active" || report.AppliedRevision != 5 || !bytesContainsJSONKey(report.PublicMaterialJSON, "public_key") {
		t.Fatalf("stale apply LKG report = %+v", report)
	}

	sameRevisionChanged := applyItem(item.InboundID, item.EffectiveTag, 2083, 5, testClientUUID)
	h.setItems([]desiredItem{sameRevisionChanged})
	if err := h.reconciler.SyncOnce(context.Background()); err == nil {
		t.Fatal("same-revision structural change unexpectedly succeeded")
	}
	if after := h.core.raw(item.EffectiveTag); string(after) != string(original) {
		t.Fatal("same-revision conflict changed runtime")
	}
	if report := h.latestReport().Deployments[0]; report.Status != "degraded" || report.AppliedRevision != 5 || report.ErrorCode != "revision_conflict" || !bytesContainsJSONKey(report.PublicMaterialJSON, "public_key") {
		t.Fatalf("revision conflict LKG report = %+v", report)
	}

	staleDelete := desiredItem{InboundID: item.InboundID, Action: "delete", DesiredRevision: 4, EffectiveTag: item.EffectiveTag, EffectivePort: item.EffectivePort}
	h.setItems([]desiredItem{staleDelete})
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatalf("stale tombstone should report newer active state: %v", err)
	}
	if len(h.core.raw(item.EffectiveTag)) == 0 {
		t.Fatal("stale tombstone removed newer runtime")
	}
	if report := h.latestReport().Deployments[0]; report.Status != "active" || report.AppliedRevision != 5 {
		t.Fatalf("stale tombstone LKG report = %+v", report)
	}

	delete6 := desiredItem{InboundID: item.InboundID, Action: "delete", DesiredRevision: 6, EffectiveTag: item.EffectiveTag, EffectivePort: item.EffectivePort}
	h.setItems([]desiredItem{delete6})
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(h.core.raw(item.EffectiveTag)) != 0 {
		t.Fatal("newer tombstone did not remove runtime")
	}
	if tombstone, ok := h.manager.ControllerTombstone(item.EffectiveTag); !ok || tombstone.DesiredRevision != 6 {
		t.Fatalf("durable tombstone = %+v, ok=%v", tombstone, ok)
	}

	staleResurrection := applyItem(item.InboundID, item.EffectiveTag, 2053, 5, testClientUUID)
	h.setItems([]desiredItem{staleResurrection})
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatalf("stale resurrection should preserve deleted observation: %v", err)
	}
	if len(h.core.raw(item.EffectiveTag)) != 0 {
		t.Fatal("stale apply resurrected tombstoned runtime")
	}
	if report := h.latestReport().Deployments[0]; report.Status != "deleted" || report.AppliedRevision != 6 {
		t.Fatalf("tombstone LKG report = %+v", report)
	}
}

func TestControllerRejectsNamespaceFlowAndWrongServerIdentity(t *testing.T) {
	outside := applyItem("catalog-outside", "outside", 2053, 1, testClientUUID)
	outside.EffectiveTag = "legacy-outside"
	h := newControllerHarness(t, []desiredItem{outside})
	if err := h.reconciler.SyncOnce(context.Background()); err == nil {
		t.Fatal("non-gx controller tag unexpectedly succeeded")
	}
	if len(h.inventory.All()) != 0 {
		t.Fatal("non-gx tag mutated inventory")
	}

	vision := applyItem("catalog-xhttp-flow", "xhttp-flow", 2053, 1, testClientUUID)
	vision.UserFlow = "xtls-rprx-vision"
	h = newControllerHarness(t, []desiredItem{vision})
	if err := h.reconciler.SyncOnce(context.Background()); err == nil {
		t.Fatal("XHTTP Vision unexpectedly succeeded")
	}
	if len(h.inventory.All()) != 0 {
		t.Fatal("invalid XHTTP flow mutated inventory")
	}

	identity := applyItem("catalog-identity", "identity", 2053, 1, testClientUUID)
	h = newControllerHarness(t, []desiredItem{identity})
	h.reconciler.cfg.NodeID = "another-server"
	if err := h.reconciler.SyncOnce(context.Background()); err == nil {
		t.Fatal("wrong server-scoped manifest unexpectedly succeeded")
	}
	if len(h.inventory.All()) != 0 {
		t.Fatal("wrong server manifest mutated inventory")
	}

	h = newControllerHarness(t, []desiredItem{identity})
	h.mu.Lock()
	h.serverID = ""
	h.mu.Unlock()
	if err := h.reconciler.SyncOnce(context.Background()); err == nil {
		t.Fatal("manifest without a server identity unexpectedly succeeded")
	}
	if len(h.inventory.All()) != 0 {
		t.Fatal("manifest without a server identity mutated inventory")
	}
}

func TestControllerNeverFollowsRedirectWithNodeCredentials(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Service-Token") == "" || r.Header.Get("X-Node-Secret") == "" {
			t.Error("initial controller request omitted credentials")
		}
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	h := newControllerHarness(t, nil)
	h.reconciler.baseURL = redirector.URL
	h.reconciler.http = redirector.Client()
	h.reconciler.http.CheckRedirect = rejectRedirect
	if err := h.reconciler.SyncOnce(context.Background()); err == nil {
		t.Fatal("redirected controller response unexpectedly succeeded")
	}
	if redirected.Load() {
		t.Fatal("controller followed redirect and exposed node headers")
	}
}

func TestControllerReportsOnlyPhaseOneCapabilities(t *testing.T) {
	item := applyItem("catalog-capabilities", "capabilities", 2053, 1)
	h := newControllerHarness(t, []desiredItem{item})
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	capabilities := h.latestReport().Capabilities
	if strings.Join(capabilities.SupportedTransports, ",") != "raw,xhttp" || strings.Join(capabilities.SupportedSecurities, ",") != "reality" {
		t.Fatalf("overclaimed capabilities = %+v", capabilities)
	}
	if !strings.Contains(string(capabilities.RawJSON), `"controller_tag_namespace":"gx-"`) {
		t.Fatalf("controller namespace missing from capabilities = %s", capabilities.RawJSON)
	}
}

func TestControllerUserOperationLockCoversFetchThroughRuntimeReconcile(t *testing.T) {
	coordinator := userops.New()
	item := applyItem("catalog-fetch-lock", "fetch-lock", 2053, 1, testClientUUID)
	h := newControllerHarness(t, []desiredItem{item}, coordinator)
	fetchStarted := make(chan struct{})
	releaseFetch := make(chan struct{})
	var once sync.Once
	h.mu.Lock()
	h.desiredHook = func() {
		once.Do(func() { close(fetchStarted) })
		<-releaseFetch
	}
	h.mu.Unlock()

	syncDone := make(chan error, 1)
	go func() { syncDone <- h.reconciler.SyncOnce(context.Background()) }()
	select {
	case <-fetchStarted:
	case <-time.After(time.Second):
		t.Fatal("controller fetch did not start")
	}
	directMutationRan := make(chan struct{})
	go func() {
		coordinator.Lock()
		close(directMutationRan)
		coordinator.Unlock()
	}()
	select {
	case <-directMutationRan:
		t.Fatal("direct user mutation entered after controller lock but before manifest fetch completed")
	case <-time.After(75 * time.Millisecond):
	}
	close(releaseFetch)
	if err := <-syncDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-directMutationRan:
	case <-time.After(time.Second):
		t.Fatal("direct user mutation did not resume after controller reconciliation")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func bytesContainsJSONKey(raw json.RawMessage, key string) bool {
	var object map[string]any
	if json.Unmarshal(raw, &object) != nil {
		return false
	}
	_, ok := object[key]
	return ok
}
