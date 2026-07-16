package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardex/node-agent/internal/config"
	"github.com/guardex/node-agent/internal/inbound"
	"github.com/guardex/node-agent/internal/inboundsync"
	"github.com/guardex/node-agent/internal/store"
	"github.com/guardex/node-agent/internal/userops"
	"github.com/guardex/node-agent/internal/xray"
)

type apiFakeCore struct {
	mu          sync.Mutex
	inbounds    map[string][]byte
	removeCalls []string
}

type blockingUserRuntime struct {
	entered chan struct{}
	release chan struct{}
}

type notFoundUserRuntime struct{}

type recordingUserRuntime struct {
	addCalls int
}

func (r *recordingUserRuntime) AddUser(context.Context, xray.AddUserParams) error {
	r.addCalls++
	return nil
}

func (r *recordingUserRuntime) RemoveUser(context.Context, string, string) error { return nil }

func (notFoundUserRuntime) AddUser(context.Context, xray.AddUserParams) error { return nil }

func (notFoundUserRuntime) RemoveUser(context.Context, string, string) error {
	return errors.New("not enough information for making a decision")
}

func (f *blockingUserRuntime) AddUser(context.Context, xray.AddUserParams) error {
	close(f.entered)
	<-f.release
	return nil
}

func (f *blockingUserRuntime) RemoveUser(context.Context, string, string) error {
	close(f.entered)
	<-f.release
	return nil
}

func (f *apiFakeCore) AddInboundFromJSON(_ context.Context, raw []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
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

func (f *apiFakeCore) RemoveInbound(_ context.Context, tag string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removeCalls = append(f.removeCalls, tag)
	if _, exists := f.inbounds[tag]; !exists {
		return errors.New("not found")
	}
	delete(f.inbounds, tag)
	return nil
}

func (f *apiFakeCore) ListInboundTags(_ context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tags := make([]string, 0, len(f.inbounds))
	for tag := range f.inbounds {
		tags = append(tags, tag)
	}
	return tags, nil
}

func newInboundHandlers(t *testing.T) (*handlers, *apiFakeCore) {
	t.Helper()
	core := &apiFakeCore{inbounds: make(map[string][]byte)}
	inventory := store.NewInboundStore(filepath.Join(t.TempDir(), "inbounds.json"))
	manager := inboundsync.New(core, inventory, time.Minute, "vless-in", "api")
	return &handlers{cfg: &config.Config{Version: "test", XrayCoreVersion: "26.6.1"}, inbounds: manager}, core
}

const keylessRealityRequest = `{
	"tag":"api-test","port":443,"protocol":"vless",
	"settings":{"clients":[],"decryption":"none"},
	"streamSettings":{"network":"tcp","security":"reality","realitySettings":{
		"dest":"www.example.com:443","serverNames":["www.example.com"],
		"privateKey":"","shortIds":[]
	}}
}`

func TestAddAndListInboundsNeverExposePrivateKey(t *testing.T) {
	h, _ := newInboundHandlers(t)
	request := httptest.NewRequest(http.MethodPost, "/v1/inbounds", strings.NewReader(keylessRealityRequest))
	response := httptest.NewRecorder()
	h.addInbound(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("POST status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "privateKey") || strings.Contains(response.Body.String(), "private_key") {
		t.Fatalf("POST leaked private key: %s", response.Body.String())
	}
	var addResult map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &addResult); err != nil {
		t.Fatal(err)
	}
	if addResult["public_key"] == "" || addResult["short_id"] == "" {
		t.Fatalf("POST did not return safe public material: %s", response.Body.String())
	}
	firstPublic := addResult["public_key"]
	firstShortID := addResult["short_id"]
	firstDesiredDigest := addResult["desired_digest"]
	retryResponse := httptest.NewRecorder()
	h.addInbound(retryResponse, httptest.NewRequest(http.MethodPost, "/v1/inbounds", strings.NewReader(keylessRealityRequest)))
	if retryResponse.Code != http.StatusOK {
		t.Fatalf("retry status=%d body=%s", retryResponse.Code, retryResponse.Body.String())
	}
	var retryResult map[string]any
	if err := json.Unmarshal(retryResponse.Body.Bytes(), &retryResult); err != nil {
		t.Fatal(err)
	}
	if retryResult["public_key"] != firstPublic || retryResult["short_id"] != firstShortID {
		t.Fatalf("idempotent POST rotated credentials: first=%v/%v retry=%v/%v", firstPublic, firstShortID, retryResult["public_key"], retryResult["short_id"])
	}
	if retryResult["desired_digest"] != firstDesiredDigest {
		t.Fatalf("idempotent POST changed desired digest: first=%v retry=%v", firstDesiredDigest, retryResult["desired_digest"])
	}

	listResponse := httptest.NewRecorder()
	h.listInbounds(listResponse, httptest.NewRequest(http.MethodGet, "/v1/inbounds", nil))
	if listResponse.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
	if strings.Contains(listResponse.Body.String(), "privateKey") || strings.Contains(listResponse.Body.String(), "private_key") {
		t.Fatalf("GET leaked private key: %s", listResponse.Body.String())
	}
	if !strings.Contains(listResponse.Body.String(), `"network":"tcp"`) || !strings.Contains(listResponse.Body.String(), `"applied":true`) {
		t.Fatalf("GET omitted status metadata: %s", listResponse.Body.String())
	}
	if !strings.Contains(listResponse.Body.String(), `"controller_polling":false`) {
		t.Fatalf("GET must describe the not-yet-wired pull capability honestly: %s", listResponse.Body.String())
	}
}

func TestInboundCapabilitiesAdvertiseManagedGRPCReality(t *testing.T) {
	capabilities := inboundCapabilities(&config.Config{})
	networks, ok := capabilities["stream_networks"].([]string)
	if !ok || strings.Join(networks, ",") != "raw,xhttp,grpc" {
		t.Fatalf("stream networks = %#v", capabilities["stream_networks"])
	}
	securities, ok := capabilities["stream_securities"].([]string)
	if !ok || strings.Join(securities, ",") != "reality" {
		t.Fatalf("stream securities = %#v", capabilities["stream_securities"])
	}
}

func TestDirectUserAPIRejectsFlowForManagedXHTTPAndGRPC(t *testing.T) {
	configs := map[string]string{
		"xhttp": `{
			"tag":"api-xhttp","port":2053,"protocol":"vless",
			"settings":{"clients":[],"decryption":"none"},
			"streamSettings":{"network":"xhttp","security":"reality","realitySettings":{
				"dest":"www.example.com:443","serverNames":["www.example.com"]
			},"xhttpSettings":{"path":"/assets/sync"}}
		}`,
		"grpc": `{
			"tag":"api-grpc","port":8443,"protocol":"vless",
			"settings":{"clients":[],"decryption":"none"},
			"streamSettings":{"network":"grpc","security":"reality","realitySettings":{
				"dest":"www.example.com:443","serverNames":["www.example.com"]
			},"grpcSettings":{"serviceName":"guardex.sync-v1"}}
		}`,
	}
	for network, configJSON := range configs {
		t.Run(network, func(t *testing.T) {
			h, _ := newInboundHandlers(t)
			apply := httptest.NewRecorder()
			h.addInbound(apply, httptest.NewRequest(http.MethodPost, "/v1/inbounds", strings.NewReader(configJSON)))
			if apply.Code != http.StatusOK {
				t.Fatalf("apply status=%d body=%s", apply.Code, apply.Body.String())
			}
			runtime := &recordingUserRuntime{}
			h.userCore = runtime
			requestBody := `{"uuid":"6f8d0c5b-6c62-4b35-9231-b2af180b5284","flow":"xtls-rprx-vision","inbound_tag":"api-` + network + `"}`
			response := httptest.NewRecorder()
			h.addUser(response, httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(requestBody)))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if runtime.addCalls != 0 {
				t.Fatal("invalid flow reached the user runtime")
			}
		})
	}
}

func TestAddInboundRejectsUnapprovedProtocolBeforeCore(t *testing.T) {
	h, core := newInboundHandlers(t)
	body := strings.Replace(keylessRealityRequest, `"protocol":"vless"`, `"protocol":"shadowsocks"`, 1)
	response := httptest.NewRecorder()
	h.addInbound(response, httptest.NewRequest(http.MethodPost, "/v1/inbounds", strings.NewReader(body)))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(core.inbounds) != 0 {
		t.Fatal("unsafe protocol reached core")
	}
}

func TestDeleteDoesNotTouchStaticInbound(t *testing.T) {
	h, core := newInboundHandlers(t)
	core.inbounds["vless-in"] = []byte("static")
	request := httptest.NewRequest(http.MethodDelete, "/v1/inbounds/vless-in", nil)
	request.SetPathValue("tag", "vless-in")
	response := httptest.NewRecorder()
	h.removeInbound(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(core.removeCalls) != 0 {
		t.Fatalf("static inbound reached core removal: %v", core.removeCalls)
	}
}

func TestLegacyInboundAPICannotReplaceOrDeleteControllerOwnedTag(t *testing.T) {
	h, core := newInboundHandlers(t)
	body := strings.Replace(keylessRealityRequest, `"tag":"api-test"`, `"tag":"gx-controller-api"`, 1)
	body = strings.Replace(body, `"port":443`, `"port":2053`, 1)
	create := httptest.NewRecorder()
	h.addInbound(create, httptest.NewRequest(http.MethodPost, "/v1/inbounds", strings.NewReader(body)))
	if create.Code != http.StatusOK {
		t.Fatalf("manual transition create status=%d body=%s", create.Code, create.Body.String())
	}
	cfg, ok := h.inbounds.ManagedConfig("gx-controller-api")
	if !ok {
		t.Fatal("manual transition config missing")
	}
	state := store.InboundControllerState{
		InboundID:              "catalog-api-owned",
		DesiredRevision:        1,
		AppliedRevision:        1,
		Status:                 "active",
		PublicMaterialJSON:     json.RawMessage(`{"public_key":"public"}`),
		ClientParamsJSON:       json.RawMessage(`{}`),
		AppliedClientSetSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	if _, err := h.inbounds.ApplyControllerDesiredWithResult(context.Background(), cfg, cfg.Digest, state); err != nil {
		t.Fatalf("controller adoption failed: %v", err)
	}

	replace := httptest.NewRecorder()
	h.addInbound(replace, httptest.NewRequest(http.MethodPost, "/v1/inbounds", strings.NewReader(body)))
	if replace.Code != http.StatusConflict || !strings.Contains(replace.Body.String(), "managed by controller") {
		t.Fatalf("legacy replace status=%d body=%s", replace.Code, replace.Body.String())
	}
	removeRequest := httptest.NewRequest(http.MethodDelete, "/v1/inbounds/gx-controller-api", nil)
	removeRequest.SetPathValue("tag", "gx-controller-api")
	remove := httptest.NewRecorder()
	h.removeInbound(remove, removeRequest)
	if remove.Code != http.StatusConflict || !strings.Contains(remove.Body.String(), "managed by controller") {
		t.Fatalf("legacy delete status=%d body=%s", remove.Code, remove.Body.String())
	}
	if _, exists := core.inbounds["gx-controller-api"]; !exists {
		t.Fatal("legacy API changed controller-owned runtime")
	}
}

func TestDirectUserAPIMutationsHonorSharedCoordinator(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			coordinator := userops.New()
			coordinator.Lock()
			runtime := &blockingUserRuntime{entered: make(chan struct{}), release: make(chan struct{})}
			userStore := store.New(filepath.Join(t.TempDir(), "users.json"))
			h := &handlers{
				cfg:      &config.Config{DefaultInboundTag: "vless-in"},
				store:    userStore,
				userOps:  coordinator,
				userCore: runtime,
			}
			response := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				defer close(done)
				if method == http.MethodPost {
					h.addUser(response, httptest.NewRequest(method, "/v1/users", strings.NewReader(`{"uuid":"6f8d0c5b-6c62-4b35-9231-b2af180b5284"}`)))
					return
				}
				request := httptest.NewRequest(method, "/v1/users/6f8d0c5b-6c62-4b35-9231-b2af180b5284", nil)
				request.SetPathValue("uuid", "6f8d0c5b-6c62-4b35-9231-b2af180b5284")
				h.removeUser(response, request)
			}()
			select {
			case <-runtime.entered:
				t.Fatal("direct user mutation reached Xray while shared coordinator was held")
			case <-time.After(50 * time.Millisecond):
			}
			coordinator.Unlock()
			select {
			case <-runtime.entered:
			case <-time.After(time.Second):
				t.Fatal("direct user mutation did not resume after coordinator unlock")
			}
			close(runtime.release)
			<-done
			if response.Code != http.StatusOK {
				t.Fatalf("direct user mutation status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestDirectUserDeleteIsIdempotentAfterControllerReconcile(t *testing.T) {
	userStore := store.New(filepath.Join(t.TempDir(), "users.json"))
	h := &handlers{
		cfg:      &config.Config{DefaultInboundTag: "gx-delete-idempotent"},
		store:    userStore,
		userOps:  userops.New(),
		userCore: notFoundUserRuntime{},
	}
	request := httptest.NewRequest(http.MethodDelete, "/v1/users/6f8d0c5b-6c62-4b35-9231-b2af180b5284", nil)
	request.SetPathValue("uuid", "6f8d0c5b-6c62-4b35-9231-b2af180b5284")
	response := httptest.NewRecorder()
	h.removeUser(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("idempotent delete status=%d body=%s", response.Code, response.Body.String())
	}
}
