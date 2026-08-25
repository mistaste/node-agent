package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guardex/node-agent/internal/config"
	"github.com/guardex/node-agent/internal/metrics"
)

func TestMetricsOnlyServerIsAuthenticatedAndLeastPrivilege(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	cfg := &config.Config{
		Secret:      secret,
		MetricsOnly: true,
		Version:     "relay-test-revision",
		RepoDir:     t.TempDir(),
		UpdateRef:   "master",
	}
	collector := metrics.NewCollector(nil, time.Hour, "")
	server := NewMetricsOnlyServer(cfg, collector)
	handler := server.auth(server.mux)

	for _, route := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/health"},
		{http.MethodGet, "/v1/metrics"},
		{http.MethodPost, "/v1/system/update-agent"},
	} {
		unauthorized := httptest.NewRecorder()
		request := httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`))
		handler.ServeHTTP(unauthorized, request)
		if unauthorized.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s %s status = %d, want %d", route.method, route.path, unauthorized.Code, http.StatusUnauthorized)
		}
	}

	health := httptest.NewRecorder()
	healthRequest := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	healthRequest.Header.Set("Authorization", "Bearer "+secret)
	handler.ServeHTTP(health, healthRequest)
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d body=%s", health.Code, health.Body.String())
	}
	var body struct {
		Status       string         `json:"status"`
		Version      string         `json:"version"`
		Mode         string         `json:"mode"`
		Capabilities map[string]any `json:"capabilities"`
	}
	if err := json.Unmarshal(health.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "ok" || body.Version != "relay-test-revision" || body.Mode != "metrics-only" {
		t.Fatalf("health body = %+v", body)
	}
	for _, capability := range []string{"host_metrics", "agent_update"} {
		if enabled, ok := body.Capabilities[capability].(bool); !ok || !enabled {
			t.Fatalf("health capability %q = %#v, want true", capability, body.Capabilities[capability])
		}
	}
	for _, capability := range []string{"xray_management", "inbound_management", "topology_management"} {
		if enabled, ok := body.Capabilities[capability].(bool); !ok || enabled {
			t.Fatalf("health capability %q = %#v, want false", capability, body.Capabilities[capability])
		}
	}

	metricsResponse := authenticatedRequest(handler, secret, http.MethodGet, "/v1/metrics", "")
	if metricsResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("warming metrics status = %d, want %d", metricsResponse.Code, http.StatusServiceUnavailable)
	}
	updateResponse := authenticatedRequest(handler, secret, http.MethodPost, "/v1/system/update-agent", `{"mode":"git-full"}`)
	if updateResponse.Code != http.StatusBadRequest {
		t.Fatalf("restricted agent update status = %d, want 400", updateResponse.Code)
	}

	for _, route := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/users"},
		{http.MethodPost, "/v1/inbounds"},
		{http.MethodPost, "/v1/system/update-xray"},
		{http.MethodPost, "/v1/system/restart"},
		{http.MethodPost, "/v1/controller/reconcile"},
	} {
		response := authenticatedRequest(handler, secret, route.method, route.path, `{}`)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s %s status = %d, want 404", route.method, route.path, response.Code)
		}
	}
}

func TestMetricsOnlyAgentUpdateNeverTouchesTopologyOrEndpointServices(t *testing.T) {
	parts, err := metricsOnlyAgentUpdateParts("master")
	if err != nil {
		t.Fatal(err)
	}
	command := strings.Join(parts, " ")
	if !strings.Contains(command, "--no-deps --build node-agent") {
		t.Fatalf("metrics-only update command = %q", command)
	}
	for _, forbidden := range []string{"topology-agent", "xray", "trusttunnel-runner", "transport-bundle-runner"} {
		if strings.Contains(command, forbidden) {
			t.Fatalf("metrics-only update command touches %s: %q", forbidden, command)
		}
	}
	for _, ref := range []string{"../master", "master;reboot", "feature//bad", "feature/"} {
		if _, err := metricsOnlyAgentUpdateParts(ref); err == nil {
			t.Fatalf("unsafe ref %q accepted", ref)
		}
	}
}

func authenticatedRequest(handler http.Handler, secret, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+secret)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
