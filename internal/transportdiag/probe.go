// Package transportdiag records phases, never raw URLs, addresses, bodies or errors.
package transportdiag

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"
)

type Event struct {
	Phase     string `json:"phase"`
	Outcome   string `json:"outcome"`
	ElapsedMS int64  `json:"elapsed_ms"`
	Status    int    `json:"http_status,omitempty"`
}

func Probe(ctx context.Context, raw string) ([]Event, error) {
	return probe(ctx, raw, nil)
}
func probe(ctx context.Context, raw string, roots *x509.CertPool) ([]Event, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("require HTTPS URL without credentials, query or fragment")
	}
	started := time.Now()
	var mu sync.Mutex
	events := []Event{}
	phase := "request"
	add := func(p, o string, status int) {
		mu.Lock()
		defer mu.Unlock()
		phase = p
		events = append(events, Event{p, o, time.Since(started).Milliseconds(), status})
	}
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { add("dns", "started", 0) },
		DNSDone: func(i httptrace.DNSDoneInfo) {
			o := "ok"
			if i.Err != nil {
				o = "failed"
			}
			add("dns", o, 0)
		},
		ConnectStart: func(string, string) { add("tcp", "started", 0) },
		ConnectDone: func(_, _ string, e error) {
			o := "ok"
			if e != nil {
				o = "failed"
			}
			add("tcp", o, 0)
		},
		TLSHandshakeStart: func() { add("tls", "started", 0) },
		TLSHandshakeDone: func(_ tls.ConnectionState, e error) {
			o := "ok"
			if e != nil {
				o = "failed"
			}
			add("tls", o, 0)
		},
		WroteRequest: func(i httptrace.WroteRequestInfo) {
			o := "waiting"
			if i.Err != nil {
				o = "failed"
			}
			add("http_headers", o, 0)
		},
		GotFirstResponseByte: func() { add("http_headers", "received", 0) },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "GET", raw, nil)
	if err != nil {
		return nil, errors.New("invalid HTTP probe request")
	}
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 8 * time.Second}
	defer tr.CloseIdleConnections()
	client := http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		mu.Lock()
		last := phase
		mu.Unlock()
		outcome := "failed"
		var cert *tls.CertificateVerificationError
		if errors.As(err, &cert) {
			outcome = "bad_certificate"
		} else if errors.Is(ctx.Err(), context.Canceled) {
			outcome = "caller_canceled"
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			outcome = "deadline"
		} else {
			var n net.Error
			if errors.As(err, &n) && n.Timeout() {
				outcome = "timeout"
			}
		}
		add(last, outcome, 0)
	} else {
		outcome := "ok"
		if resp.StatusCode >= 500 {
			outcome = "server_error"
			err = errors.New("HTTP server error")
		} else if resp.StatusCode >= 400 {
			outcome = "http_rejection"
		}
		add("http_status", outcome, resp.StatusCode)
		// Bounded metadata probe; never record response content or wait for an SSE body.
		resp.Body.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	var resultErr error
	if err != nil {
		resultErr = errors.New("transport probe failed")
	}
	return append([]Event(nil), events...), resultErr
}
func WriteJSON(w io.Writer, events []Event) error { return json.NewEncoder(w).Encode(events) }
