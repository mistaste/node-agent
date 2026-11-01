package transportdiag

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProbePhasesAndNoPayload(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		w.Write([]byte("private-secret-response"))
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	events, err := probe(context.Background(), server.URL, roots)
	if err == nil {
		t.Fatal("HTTP503 must fail the probe")
	}
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.Phase+":"+e.Outcome] = true
	}
	for _, want := range []string{"tcp:ok", "tls:ok", "http_headers:received", "http_status:server_error"} {
		if !seen[want] {
			t.Fatalf("missing %s: %#v", want, events)
		}
	}
	raw, _ := json.Marshal(events)
	for _, secret := range []string{"private-secret", server.URL, "127.0.0.1"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("private content leaked")
		}
	}
}
func TestCertificateFailureIsNotHTTPOrDNS(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer s.Close()
	events, err := Probe(context.Background(), s.URL)
	if err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	last := events[len(events)-1]
	if last.Phase != "tls" || last.Outcome != "bad_certificate" {
		t.Fatalf("%#v", events)
	}
}
func TestCallerCancelAndHeaderTimeoutAreDistinct(t *testing.T) {
	for _, cancelled := range []bool{true, false} {
		t.Run(map[bool]string{true: "cancel", false: "deadline"}[cancelled], func(t *testing.T) {
			ready := make(chan struct{})
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(ready); <-r.Context().Done() }))
			defer s.Close()
			roots := x509.NewCertPool()
			roots.AddCert(s.Certificate())
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			if cancelled {
				go func() { <-ready; cancel() }()
			}
			events, err := probe(ctx, s.URL, roots)
			if err == nil {
				t.Fatal("failed request reported success")
			}
			last := events[len(events)-1]
			want := "deadline"
			if cancelled {
				want = "caller_canceled"
			}
			if last.Phase != "http_headers" || last.Outcome != want {
				t.Fatalf("%#v", events)
			}
		})
	}
}
func TestRejectsCredentialBearingInput(t *testing.T) {
	for _, u := range []string{"http://example.com", "https://u:p@example.com", "https://example.com?token=secret", "https://example.com/#secret"} {
		if _, err := Probe(context.Background(), u); err == nil {
			t.Fatal("unsafe input accepted")
		}
	}
}
