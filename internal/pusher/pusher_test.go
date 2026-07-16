package pusher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardex/node-agent/internal/config"
	"github.com/guardex/node-agent/internal/xray"
)

func TestPusherRejectsUntrustedControllerCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	pusher := NewPusher(&config.Config{}, nil)
	response, err := pusher.http.Get(server.URL)
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil {
		t.Fatal("pusher accepted a self-signed controller certificate")
	}
}

func TestPusherDoesNotFollowRedirects(t *testing.T) {
	var reached atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	pusher := NewPusher(&config.Config{}, nil)
	response, err := pusher.http.Get(redirector.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("redirect status = %d", response.StatusCode)
	}
	if reached.Load() {
		t.Fatal("pusher followed a redirect which could expose node credentials")
	}
}

func TestPusherDoesNotStartWithPlainHTTPControllerCredentials(t *testing.T) {
	pusher := NewPusher(&config.Config{
		ControllerURL:        "http://controller.example",
		InternalServiceToken: "service-token",
		Secret:               "node-secret",
		MetricsInterval:      time.Hour,
	}, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pusher.Run(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("metrics pusher started with an unverified plain-HTTP controller")
	}
}

func TestTrafficPayloadIncludesFirstCumulativeSampleWithoutMakingItActive(t *testing.T) {
	got := trafficPayload([]xray.UserTraffic{
		{UUID: " user-1 ", Uplink: 120, Downlink: 34},
		{UUID: "", Uplink: 1, Downlink: 2},
		{UUID: "invalid-negative", Uplink: -1, Downlink: 2},
	})
	if len(got) != 1 {
		t.Fatalf("traffic payload = %+v, want one valid sample", got)
	}
	if got[0].UUID != "user-1" || got[0].Uplink != 120 || got[0].Downlink != 34 || got[0].LastSeen != "" {
		t.Fatalf("traffic sample = %+v", got[0])
	}
}

func TestMetricsPayloadSerializesTrafficCountersSeparately(t *testing.T) {
	payload := metricsPayload{
		Sessions:    0,
		ActiveUsers: []activeUserPayload{},
		UserTraffic: trafficPayload([]xray.UserTraffic{{UUID: "short-session", Uplink: 7, Downlink: 9}}),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Sessions    int                 `json:"sessions"`
		ActiveUsers []activeUserPayload `json:"active_users"`
		UserTraffic []activeUserPayload `json:"user_traffic"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Sessions != 0 || len(decoded.ActiveUsers) != 0 || len(decoded.UserTraffic) != 1 {
		t.Fatalf("decoded metrics payload = %+v", decoded)
	}
	if decoded.UserTraffic[0].UUID != "short-session" || decoded.UserTraffic[0].Uplink+decoded.UserTraffic[0].Downlink != 16 {
		t.Fatalf("decoded traffic counters = %+v", decoded.UserTraffic)
	}
}

func TestMetricsPayloadSerializesExplicitEmptyTrafficCounters(t *testing.T) {
	payload := metricsPayload{
		ActiveUsers: []activeUserPayload{},
		UserTraffic: trafficPayload(nil),
	}
	if payload.UserTraffic == nil {
		t.Fatal("trafficPayload(nil) returned nil; rolling fallback requires an explicit empty array")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	items, ok := decoded["user_traffic"].([]any)
	if !ok || len(items) != 0 {
		t.Fatalf("user_traffic JSON = %#v, want []", decoded["user_traffic"])
	}
}
