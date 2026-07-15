package pusher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardex/node-agent/internal/config"
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
