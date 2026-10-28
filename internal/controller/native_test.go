package controller

import (
	"bytes"
	"context"
	"crypto/sha256"

	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/guardex/node-agent/internal/config"
	"github.com/guardex/node-agent/internal/transportbundle"
	"github.com/guardex/node-agent/internal/trusttunnel"
	"github.com/guardex/node-agent/internal/userops"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testClientUUID = "53f47de3-9040-4c4a-818f-6a91b65eb612"
const testControllerSecret = "01234567890123456789012345678901"

type controllerHarness struct {
	t            *testing.T
	mu           sync.Mutex
	items        []desiredItem
	serverID     string
	getCalls     int
	invalidJSON  bool
	desiredHook  func()
	server       *httptest.Server
	reconciler   *Reconciler
	reports      []observedReport
	reportSignal chan struct{}
}
type fakeTrustTunnelRuntime struct {
	available bool
	state     trusttunnel.State
	applied   []trusttunnel.ApplyRequest
	removed   []string
}

func (f *fakeTrustTunnelRuntime) Available(context.Context) bool { return f.available }
func (f *fakeTrustTunnelRuntime) Apply(_ context.Context, request trusttunnel.ApplyRequest) (trusttunnel.State, error) {
	f.applied = append(f.applied, request)
	f.state = trusttunnel.State{Version: 1, InboundID: request.InboundID, Tag: request.Tag, Revision: request.Revision, Port: request.Endpoint.Port, ClientCount: len(request.Endpoint.ClientUUIDs), ClientSetSHA256: request.ClientSetSHA256}
	return f.state, nil
}
func (f *fakeTrustTunnelRuntime) Remove(_ context.Context, inboundID string, _ int64) error {
	f.removed = append(f.removed, inboundID)
	f.state = trusttunnel.State{}
	return nil
}
func (f *fakeTrustTunnelRuntime) State() (trusttunnel.State, bool) {
	return f.state, f.state.InboundID != ""
}

type fakeTransportBundleRuntime struct {
	state   transportbundle.State
	applied []transportbundle.ApplyRequest
	fail    bool
}

func (f *fakeTransportBundleRuntime) Apply(_ context.Context, request transportbundle.ApplyRequest) (transportbundle.State, error) {
	f.applied = append(f.applied, request)
	if f.fail {
		return transportbundle.State{}, errors.New("bundle failed")
	}
	f.state = transportbundle.State{Version: 1, InboundID: request.InboundID, Tag: request.Tag, Revision: request.Revision, ClientCount: len(request.Config.ClientUUIDs), ClientSetSHA256: request.ClientSetSHA256}
	return f.state, nil
}
func (f *fakeTransportBundleRuntime) Remove(_ context.Context, _ string, _ int64) error {
	f.state = transportbundle.State{}
	return nil
}
func (f *fakeTransportBundleRuntime) State() (transportbundle.State, bool) {
	return f.state, f.state.InboundID != ""
}

func newControllerHarness(t *testing.T, items []desiredItem, coordinators ...*userops.Coordinator) *controllerHarness {
	t.Helper()
	h := &controllerHarness{t: t, items: items, serverID: "server-test", reportSignal: make(chan struct{}, 16)}
	h.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Service-Token") != "service-token" || r.Header.Get("X-Node-Secret") != testControllerSecret {
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
		Secret:               testControllerSecret,
		Version:              "test-agent",
		ResyncInterval:       20 * time.Millisecond,
	}
	reconciler, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	reconciler.http = h.server.Client()
	reconciler.http.Timeout = requestTimeout
	reconciler.http.CheckRedirect = rejectRedirect
	// Fake bundle runtime has no TLS listener; live TLS verification is covered
	// separately by TestNaiveListenerPinVerifiesActualCertificate.
	reconciler.naivePin = func(context.Context, string, int) (string, error) {
		return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)), nil
	}
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

func TestControllerAppliesTrustTunnelOnlyWhenRuntimeEnabled(t *testing.T) {
	item := desiredItem{InboundID: "catalog-tt", Engine: "trusttunnel", Action: "apply", DesiredRevision: 3, EffectiveTag: "gx-trusttunnel", EffectivePort: 8443, ConfigJSON: json.RawMessage(`{"protocol":"trusttunnel","tag":"gx-trusttunnel","port":8443,"hostname":"vpn.example.com","upstream_protocol":"http2","upstream_fallback_protocol":"http3"}`), ClientUUIDs: []string{testClientUUID}}
	count := 1
	item.ClientCount = &count
	_, item.ClientSetSHA256, _ = normalizeClientUUIDs(item.ClientUUIDs)
	h := newControllerHarness(t, []desiredItem{item})
	runtime := &fakeTrustTunnelRuntime{available: true}
	h.reconciler.EnableTrustTunnel(runtime)
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runtime.applied) != 1 ||
		runtime.applied[0].Endpoint.EnableHTTP1 ||
		!runtime.applied[0].Endpoint.EnableHTTP2 ||
		!runtime.applied[0].Endpoint.EnableHTTP3 ||
		runtime.applied[0].Endpoint.IPv6Available {
		t.Fatalf("TrustTunnel apply = %+v", runtime.applied)
	}
	report := h.latestReport()
	if len(report.Deployments) != 1 || report.Deployments[0].Status != "active" || report.Deployments[0].AppliedClientCount != 1 {
		t.Fatalf("deployment report = %+v", report.Deployments)
	}
	if strings.Join(report.Capabilities.SupportedEngines, ",") != "trusttunnel" {
		t.Fatalf("engines = %+v", report.Capabilities.SupportedEngines)
	}
}

func TestTrustTunnelActiveReportPreservesCertificatePin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	root := t.TempDir()
	certDir := filepath.Join(root, "certs")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(certDir, "fullchain.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newControllerHarness(t, nil)
	h.reconciler.cfg.TrustTunnelRoot = root
	h.reconciler.EnableTrustTunnel(&fakeTrustTunnelRuntime{available: true})
	item := desiredItem{InboundID: "trust-pin", Engine: "trusttunnel", Action: "apply", DesiredRevision: 1, EffectivePort: 443, ConfigJSON: json.RawMessage(`{"protocol":"trusttunnel","hostname":"vpn.example.com","upstream_protocol":"http3"}`)}
	prepared, err := h.reconciler.prepareTrustTunnelApply(item, []string{testClientUUID}, "clients")
	if err != nil {
		t.Fatal(err)
	}
	report := h.reconciler.reconcileTrustTunnel(context.Background(), prepared)
	if report.Status != "active" {
		t.Fatalf("report status = %s", report.Status)
	}
	var params struct {
		Pins []string `json:"spki_pins_sha256"`
	}
	if err := json.Unmarshal(report.ClientParamsJSON, &params); err != nil {
		t.Fatal(err)
	}
	want, err := certificateSPKIPin(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(params.Pins) != 1 || params.Pins[0] != want {
		t.Fatal("active TrustTunnel report discarded certificate pin")
	}
}

func TestCertificateSPKIPinUsesCertificatePublicKey(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	certificate := server.Certificate()
	path := filepath.Join(t.TempDir(), "fullchain.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(spki)
	want := base64.StdEncoding.EncodeToString(digest[:])
	got, err := certificateSPKIPin(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("SPKI pin = %q, want %q", got, want)
	}
}

func TestControllerSeparatesPublicAndMuxListenerPorts(t *testing.T) {
	item := desiredItem{InboundID: "catalog-tt-mux", Engine: "trusttunnel", Action: "apply", DesiredRevision: 1, EffectiveTag: "gx-trusttunnel-mux", EffectivePort: 443, ConfigJSON: json.RawMessage(`{"protocol":"trusttunnel","hostname":"vpn.example.com","upstream_protocol":"http2","listen_port":8443}`), ClientUUIDs: []string{testClientUUID}}
	naive := desiredItem{InboundID: "catalog-naive-mux", Engine: "naiveproxy", Action: "apply", DesiredRevision: 1, EffectiveTag: "gx-naive-mux", EffectivePort: 443, ConfigJSON: json.RawMessage(`{"protocol":"naive","hostname":"naive.example.com","trusttunnel_hostname":"vpn.example.com","trusttunnel_port":8443,"naive_port":9443,"decoy_port":9080,"transport":"http2","security":"tls"}`), ClientUUIDs: []string{testClientUUID}}
	count := 1
	for _, desired := range []*desiredItem{&item, &naive} {
		desired.ClientCount = &count
		_, desired.ClientSetSHA256, _ = normalizeClientUUIDs(desired.ClientUUIDs)
	}
	h := newControllerHarness(t, []desiredItem{item, naive})
	runtime := &fakeTrustTunnelRuntime{available: true}
	h.reconciler.EnableTrustTunnel(runtime)
	h.reconciler.EnableTransportBundle(&fakeTransportBundleRuntime{})
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runtime.applied) != 1 || runtime.applied[0].Endpoint.Port != 8443 {
		t.Fatalf("internal TrustTunnel listener = %+v", runtime.applied)
	}
	reports := h.latestReport().Deployments
	if len(reports) != 2 || reports[0].EffectivePort != 443 || reports[1].EffectivePort != 443 {
		t.Fatalf("public effective ports = %+v, want 443", reports)
	}
}

func TestControllerAppliesNaiveProxyTransportBundle(t *testing.T) {
	item := desiredItem{InboundID: "catalog-naive", Engine: "naiveproxy", Action: "apply", DesiredRevision: 1, EffectiveTag: "gx-naive-h2", EffectivePort: 443, ConfigJSON: json.RawMessage(`{"protocol":"naive","tag":"gx-naive-h2","port":443,"hostname":"naive.node.example.com","trusttunnel_hostname":"node.example.com","trusttunnel_port":8443,"naive_port":9443,"decoy_port":9080,"transport":"http2","security":"tls"}`), ClientUUIDs: []string{testClientUUID}}
	count := 1
	item.ClientCount = &count
	_, item.ClientSetSHA256, _ = normalizeClientUUIDs(item.ClientUUIDs)
	h := newControllerHarness(t, []desiredItem{item})
	runtime := &fakeTransportBundleRuntime{}
	h.reconciler.EnableTransportBundle(runtime)
	if _, err := h.reconciler.prepareApply(item); err != nil {
		t.Fatalf("prepare NaiveProxy bundle: %v", err)
	}
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatalf("%v: %+v", err, h.latestReport().Deployments)
	}
	if len(runtime.applied) != 1 || runtime.applied[0].Config.PublicPort != 443 || runtime.applied[0].Config.NaivePort != 9443 || runtime.applied[0].Config.TrustTunnelPort != 8443 {
		t.Fatalf("NaiveProxy bundle apply = %+v", runtime.applied)
	}
	report := h.latestReport()
	if report.Deployments[0].Status != "active" || strings.Join(report.Capabilities.SupportedEngines, ",") != "naiveproxy" {
		t.Fatalf("NaiveProxy report = %+v", report)
	}
}

func TestNaiveProxyReportsCertificatePinAndRejectsMalformedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	root := t.TempDir()
	certDir := filepath.Join(root, "certs")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(certDir, "fullchain.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	item := desiredItem{InboundID: "naive-pin", Engine: "naiveproxy", EffectivePort: 443, ConfigJSON: json.RawMessage(`{"protocol":"naive","hostname":"naive.example.com","trusttunnel_hostname":"vpn.example.com","trusttunnel_port":8443,"naive_port":9443,"decoy_port":9080}`)}
	h := newControllerHarness(t, nil)
	h.reconciler.cfg.TrustTunnelRoot = root
	prepared, err := h.reconciler.prepareNaiveProxyApply(item, []string{testClientUUID}, "clients")
	if err != nil {
		t.Fatal(err)
	}
	var params struct {
		Pins []string `json:"spki_pins_sha256"`
	}
	if err := json.Unmarshal(prepared.clientParams, &params); err != nil {
		t.Fatal(err)
	}
	want, err := certificateSPKIPin(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(params.Pins) != 0 {
		t.Fatal("decoy certificate incorrectly reported as Naive")
	}
	served := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	if served == want {
		t.Fatal("fixture must distinguish decoy and listener")
	}
	h.reconciler.EnableTransportBundle(&fakeTransportBundleRuntime{})
	report := h.reconciler.reconcileNaiveProxy(context.Background(), prepared)
	if err := json.Unmarshal(report.ClientParamsJSON, &params); err != nil {
		t.Fatal(err)
	}
	if report.Status != "active" || len(params.Pins) != 1 || params.Pins[0] != served {
		t.Fatal("active reconciliation did not report actual listener pin")
	}
	h.reconciler.naivePin = func(context.Context, string, int) (string, error) { return "", errors.New("TLS rejected") }
	if failed := h.reconciler.reconcileNaiveProxy(context.Background(), prepared); failed.Status == "active" {
		t.Fatal("failed certificate probe reported active")
	}
	if err := os.WriteFile(path, []byte("malformed certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.reconciler.prepareNaiveProxyApply(item, []string{testClientUUID}, "clients"); err == nil {
		t.Fatal("malformed certificate accepted")
	}
}

func TestControllerRestoresPublicTrustTunnelWhenNaiveBundleFails(t *testing.T) {
	trust := desiredItem{InboundID: "catalog-tt", Engine: "trusttunnel", Action: "apply", DesiredRevision: 2, EffectiveTag: "gx-trusttunnel", EffectivePort: 443, ConfigJSON: json.RawMessage(`{"protocol":"trusttunnel","hostname":"node.example.com","upstream_protocol":"http2","listen_port":8443}`), ClientUUIDs: []string{testClientUUID}}
	naive := desiredItem{InboundID: "catalog-naive", Engine: "naiveproxy", Action: "apply", DesiredRevision: 1, EffectiveTag: "gx-naive-h2", EffectivePort: 443, ConfigJSON: json.RawMessage(`{"protocol":"naive","tag":"gx-naive-h2","port":443,"hostname":"naive.node.example.com","trusttunnel_hostname":"node.example.com","trusttunnel_port":8443,"naive_port":9443,"decoy_port":9080,"transport":"http2","security":"tls"}`), ClientUUIDs: []string{testClientUUID}}
	count := 1
	for _, item := range []*desiredItem{&trust, &naive} {
		item.ClientCount = &count
		_, item.ClientSetSHA256, _ = normalizeClientUUIDs(item.ClientUUIDs)
	}
	h := newControllerHarness(t, []desiredItem{naive, trust})
	trustRuntime := &fakeTrustTunnelRuntime{available: true}
	h.reconciler.EnableTrustTunnel(trustRuntime)
	h.reconciler.EnableTransportBundle(&fakeTransportBundleRuntime{fail: true})
	if err := h.reconciler.SyncOnce(context.Background()); err == nil {
		t.Fatal("expected NaiveProxy activation failure")
	}
	if len(trustRuntime.applied) != 2 || trustRuntime.applied[0].Endpoint.Port != 8443 || trustRuntime.applied[1].Endpoint.Port != 443 {
		t.Fatalf("TrustTunnel rollback sequence = %+v", trustRuntime.applied)
	}
}

func TestControllerRestoresPublicTrustTunnelWhenNaiveBundleIsDeleted(t *testing.T) {
	trust := desiredItem{InboundID: "catalog-tt", Engine: "trusttunnel", Action: "apply", DesiredRevision: 2, EffectiveTag: "gx-trusttunnel", EffectivePort: 443, ConfigJSON: json.RawMessage(`{"protocol":"trusttunnel","hostname":"node.example.com","upstream_protocol":"http2","listen_port":8443}`), ClientUUIDs: []string{testClientUUID}}
	naive := desiredItem{InboundID: "catalog-naive", Engine: "naiveproxy", Action: "delete", DesiredRevision: 2, EffectiveTag: "gx-naive-h2", EffectivePort: 443}
	count := 1
	trust.ClientCount = &count
	_, trust.ClientSetSHA256, _ = normalizeClientUUIDs(trust.ClientUUIDs)
	zero := 0
	naive.ClientCount = &zero
	naive.ClientSetSHA256 = emptyClientSetHash()
	h := newControllerHarness(t, []desiredItem{naive, trust})
	trustRuntime := &fakeTrustTunnelRuntime{available: true}
	bundleRuntime := &fakeTransportBundleRuntime{state: transportbundle.State{Version: 1, InboundID: naive.InboundID, Revision: 1}}
	h.reconciler.EnableTrustTunnel(trustRuntime)
	h.reconciler.EnableTransportBundle(bundleRuntime)
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(trustRuntime.applied) != 1 || trustRuntime.applied[0].Endpoint.Port != 443 {
		t.Fatalf("TrustTunnel public listener = %+v", trustRuntime.applied)
	}
	if _, active := bundleRuntime.State(); active {
		t.Fatal("Naive bundle remained active after tombstone")
	}
}

func TestControllerRejectsTrustTunnelWithoutRuntimeBeforeMutation(t *testing.T) {
	item := desiredItem{InboundID: "catalog-tt", Engine: "trusttunnel", Action: "apply", DesiredRevision: 1, EffectiveTag: "gx-trusttunnel", EffectivePort: 8443, ConfigJSON: json.RawMessage(`{"protocol":"trusttunnel","hostname":"vpn.example.com","upstream_protocol":"http2"}`)}
	h := newControllerHarness(t, []desiredItem{item})
	if err := h.reconciler.SyncOnce(context.Background()); err == nil {
		t.Fatal("expected unavailable engine rejection")
	}
	if got := h.latestReport().Deployments[0].ErrorCode; got != "engine_unavailable" {
		t.Fatalf("error code = %q", got)
	}
}

func TestControllerEnablesTrustTunnelIPv6OnlyWhenExplicit(t *testing.T) {
	item := desiredItem{InboundID: "catalog-tt-ipv6", Engine: "trusttunnel", Action: "apply", DesiredRevision: 1, EffectiveTag: "gx-trusttunnel-ipv6", EffectivePort: 8443, ConfigJSON: json.RawMessage(`{"protocol":"trusttunnel","hostname":"vpn.example.com","upstream_protocol":"http2","has_ipv6":true}`), ClientUUIDs: []string{testClientUUID}}
	count := 1
	item.ClientCount = &count
	_, item.ClientSetSHA256, _ = normalizeClientUUIDs(item.ClientUUIDs)
	h := newControllerHarness(t, []desiredItem{item})
	runtime := &fakeTrustTunnelRuntime{available: true}
	h.reconciler.EnableTrustTunnel(runtime)
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runtime.applied) != 1 || !runtime.applied[0].Endpoint.IPv6Available {
		t.Fatalf("explicit IPv6 capability was not applied: %+v", runtime.applied)
	}
}

func TestControllerRemovesAppliedTrustTunnelAfterCapabilityLoss(t *testing.T) {
	item := desiredItem{InboundID: "catalog-tt", Engine: "trusttunnel", Action: "delete", DesiredRevision: 4, EffectiveTag: "gx-trusttunnel", EffectivePort: 8443}
	h := newControllerHarness(t, []desiredItem{item})
	runtime := &fakeTrustTunnelRuntime{
		available: false,
		state:     trusttunnel.State{Version: 1, InboundID: item.InboundID, Tag: item.EffectiveTag, Revision: 3, Port: item.EffectivePort},
	}
	h.reconciler.EnableTrustTunnelCleanup(runtime)
	if err := h.reconciler.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runtime.removed) != 1 || runtime.removed[0] != item.InboundID {
		t.Fatalf("TrustTunnel capability-loss cleanup = %+v", runtime.removed)
	}
	report := h.latestReport()
	if len(report.Deployments) != 1 || report.Deployments[0].Status != "deleted" {
		t.Fatalf("deployment report = %+v", report.Deployments)
	}
	if strings.Join(report.Capabilities.SupportedEngines, ",") != "" {
		t.Fatalf("engines after capability loss = %+v", report.Capabilities.SupportedEngines)
	}
}

func TestControllerRejectsMultipleTrustTunnelRoutesBeforeMutation(t *testing.T) {
	first := desiredItem{InboundID: "catalog-tt-1", Engine: "trusttunnel", Action: "apply", DesiredRevision: 1, EffectiveTag: "gx-trusttunnel-1", EffectivePort: 8443, ConfigJSON: json.RawMessage(`{"protocol":"trusttunnel","hostname":"one.example.com","upstream_protocol":"http2"}`)}
	second := desiredItem{InboundID: "catalog-tt-2", Engine: "trusttunnel", Action: "apply", DesiredRevision: 1, EffectiveTag: "gx-trusttunnel-2", EffectivePort: 9443, ConfigJSON: json.RawMessage(`{"protocol":"trusttunnel","hostname":"two.example.com","upstream_protocol":"http2"}`)}
	h := newControllerHarness(t, []desiredItem{first, second})
	runtime := &fakeTrustTunnelRuntime{available: true}
	h.reconciler.EnableTrustTunnel(runtime)
	if err := h.reconciler.SyncOnce(context.Background()); err == nil {
		t.Fatal("expected multiple runtime instance rejection")
	}
	if len(runtime.applied) != 0 {
		t.Fatalf("manifest partially mutated runtime: %+v", runtime.applied)
	}
	for _, deployment := range h.latestReport().Deployments {
		if deployment.ErrorCode != "engine_instance_conflict" {
			t.Fatalf("deployment = %+v", deployment)
		}
	}
}

func TestRetiredEngineCannotMutateNativeEndpoint(t *testing.T) {
	native := desiredItem{InboundID: "native", Engine: "trusttunnel", Action: "apply", DesiredRevision: 1, EffectiveTag: "gx-native", EffectivePort: 443, ConfigJSON: json.RawMessage(`{"protocol":"trusttunnel","hostname":"node.example.com","upstream_protocol":"http2"}`)}
	retired := native
	retired.InboundID = "retired"
	retired.Engine = "xray"
	retired.EffectiveTag = "gx-retired"
	retired.EffectivePort = 8443
	h := newControllerHarness(t, []desiredItem{native, retired})
	runtime := &fakeTrustTunnelRuntime{available: true}
	h.reconciler.EnableTrustTunnel(runtime)
	if err := h.reconciler.SyncOnce(context.Background()); err == nil {
		t.Fatal("retired engine accepted")
	}
	if len(runtime.applied) != 0 {
		t.Fatal("partial unsafe manifest applied")
	}
}
