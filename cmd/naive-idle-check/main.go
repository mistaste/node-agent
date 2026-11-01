// Hermetic HTTP/2 CONNECT acceptance against an actual supplied Caddy binary.
// Only loopback listeners, generated TLS trust and synthetic data are used.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type result struct {
	Scenario    string  `json:"scenario"`
	IdleSeconds float64 `json:"idle_seconds"`
	Outcome     string  `json:"outcome"`
	Stage       string  `json:"stage"`
	ElapsedMS   int64   `json:"elapsed_ms"`
}
type tunnel struct {
	io.Reader
	io.Writer
	close func()
}

func (t *tunnel) Close() error                     { t.close(); return nil }
func (t *tunnel) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (t *tunnel) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (t *tunnel) SetDeadline(time.Time) error      { return errors.New("use owning context deadline") }
func (t *tunnel) SetReadDeadline(time.Time) error  { return errors.New("use owning context deadline") }
func (t *tunnel) SetWriteDeadline(time.Time) error { return errors.New("use owning context deadline") }

func openTunnel(ctx context.Context, proxy, target string) (*tunnel, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, err
	}
	tr := &http2.Transport{AllowHTTP: true}
	cc, err := tr.NewClientConn(raw)
	if err != nil {
		raw.Close()
		return nil, err
	}
	reader, writer := io.Pipe()
	req := (&http.Request{Method: "CONNECT", URL: &url.URL{Scheme: "http", Host: target}, Host: target, Body: reader, ContentLength: -1, Header: make(http.Header)}).WithContext(ctx)
	response, err := cc.RoundTrip(req)
	if err != nil {
		writer.Close()
		reader.Close()
		raw.Close()
		return nil, err
	}
	if response.StatusCode != 200 {
		response.Body.Close()
		writer.Close()
		reader.Close()
		raw.Close()
		return nil, fmt.Errorf("CONNECT status %d", response.StatusCode)
	}
	return &tunnel{Reader: response.Body, Writer: writer, close: func() { writer.Close(); reader.Close(); response.Body.Close(); raw.Close() }}, nil
}

func runScenario(proxy, kind string, idle time.Duration) result {
	started := time.Now()
	out := result{Scenario: kind, IdleSeconds: idle.Seconds(), Outcome: "fail", Stage: "connect"}
	finish := func(stage string, err error) result {
		out.Stage = stage
		out.ElapsedMS = time.Since(started).Milliseconds()
		if err == nil {
			out.Outcome = "pass"
		}
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), idle+15*time.Second)
	defer cancel()
	if kind == "duplex_after_idle" || kind == "cancel_idle" {
		origin, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return finish("origin", err)
		}
		defer origin.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			c, e := origin.Accept()
			if e != nil {
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(idle + 15*time.Second))
			io.Copy(c, c)
		}()
		conn, err := openTunnel(ctx, proxy, origin.Addr().String())
		if err != nil {
			return finish("connect", err)
		}
		defer conn.Close()
		exchange := func(marker string) error {
			if _, e := io.WriteString(conn, marker); e != nil {
				return e
			}
			got := make([]byte, len(marker))
			_, e := io.ReadFull(conn, got)
			if e == nil && string(got) != marker {
				e = errors.New("payload mismatch")
			}
			return e
		}
		if err = exchange("before-idle"); err != nil {
			return finish("before_idle", err)
		}
		if kind == "cancel_idle" {
			cancel()
			conn.Close()
			select {
			case <-done:
				return finish("caller_canceled", nil)
			case <-time.After(3 * time.Second):
				return finish("cancel_cleanup", errors.New("origin did not close"))
			}
		}
		select {
		case <-ctx.Done():
			return finish("idle", ctx.Err())
		case <-time.After(idle):
		}
		return finish("resume_bidirectional", exchange("after-idle"))
	}
	// Application TLS and a quiet streaming response inside the CONNECT tunnel.
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: before\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			return
		case <-time.After(idle):
		}
		fmt.Fprint(w, "data: after\n\n")
		w.(http.Flusher).Flush()
	}))
	defer origin.Close()
	target := strings.TrimPrefix(origin.URL, "https://")
	conn, err := openTunnel(ctx, proxy, target)
	if err != nil {
		return finish("connect", err)
	}
	defer conn.Close()
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	secure := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12})
	if err = secure.HandshakeContext(ctx); err != nil {
		return finish("tls", err)
	}
	if _, err = io.WriteString(secure, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
		return finish("request", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(secure), nil)
	if err != nil {
		return finish("response_headers", err)
	}
	defer response.Body.Close()
	stream := bufio.NewReader(response.Body)
	before, err := stream.ReadString('\n')
	if err != nil || before != "data: before\n" {
		return finish("stream_start", errors.New("missing first event"))
	}
	// Read through the empty line and await the next event with no client data.
	if _, err = stream.ReadString('\n'); err != nil {
		return finish("stream_start", err)
	}
	after, err := stream.ReadString('\n')
	if err == nil && after != "data: after\n" {
		err = errors.New("missing resumed event")
	}
	if time.Since(started) < idle {
		return finish("idle_not_exercised", errors.New("stream resumed too soon"))
	}
	return finish("quiet_tls_stream_resume", err)
}

func startCaddy(binary, dir string) (string, func(), error) {
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	addr := reserve.Addr().String()
	reserve.Close()
	config := map[string]any{"admin": map[string]any{"disabled": true}, "apps": map[string]any{"http": map[string]any{"servers": map[string]any{"acceptance": map[string]any{
		"listen": []string{addr}, "protocols": []string{"h1", "h2c"}, "routes": []any{
			map[string]any{"match": []any{map[string]any{"path": []string{"/health"}}}, "handle": []any{map[string]any{"handler": "static_response", "body": "ok"}}},
			map[string]any{"handle": []any{map[string]any{"handler": "forward_proxy", "hide_ip": true, "hide_via": true, "acl": []any{map[string]any{"allow": true, "subjects": []string{"127.0.0.1"}}}}}},
		}}}}}}
	data, err := json.Marshal(config)
	if err != nil {
		return "", nil, err
	}
	path := filepath.Join(dir, "caddy.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		return "", nil, err
	}
	log, err := os.OpenFile(filepath.Join(dir, "caddy.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return "", nil, err
	}
	cmd := exec.Command(binary, "run", "--config", path)
	cmd.Stdout = log
	cmd.Stderr = log
	if err = cmd.Start(); err != nil {
		log.Close()
		return "", nil, err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	stop := func() { cmd.Process.Kill(); <-exited; log.Close() }
	client := http.Client{Timeout: 200 * time.Millisecond}
	for i := 0; i < 50; i++ {
		r, e := client.Get("http://" + addr + "/health")
		if e == nil {
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
			if r.StatusCode == 200 {
				return addr, stop, nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	stop()
	return "", nil, errors.New("Caddy did not become ready; inspect private caddy.log")
}
func main() {
	binary := flag.String("caddy", "", "absolute Caddy binary path")
	durations := flag.String("idle", "90s,180s,300s", "comma separated idle windows")
	flag.Parse()
	if !filepath.IsAbs(*binary) {
		fmt.Fprintln(os.Stderr, "absolute -caddy path required")
		os.Exit(2)
	}
	var windows []time.Duration
	for _, v := range strings.Split(*durations, ",") {
		d, e := time.ParseDuration(v)
		if e != nil || d <= 0 || d > 10*time.Minute {
			fmt.Fprintln(os.Stderr, "idle windows must be positive and <=10m")
			os.Exit(2)
		}
		windows = append(windows, d)
	}
	dir, err := os.MkdirTemp("", "guardex-naive-idle-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	proxy, stop, err := startCaddy(*binary, dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer stop()
	var wg sync.WaitGroup
	results := make(chan result, len(windows)*2+1)
	for _, idle := range windows {
		for _, kind := range []string{"duplex_after_idle", "quiet_tls_stream"} {
			wg.Add(1)
			go func(k string, d time.Duration) { defer wg.Done(); results <- runScenario(proxy, k, d) }(kind, idle)
		}
	}
	wg.Add(1)
	go func() { defer wg.Done(); results <- runScenario(proxy, "cancel_idle", time.Second) }()
	go func() { wg.Wait(); close(results) }()
	failed := false
	for r := range results {
		json.NewEncoder(os.Stdout).Encode(r)
		if r.Outcome != "pass" {
			failed = true
		}
	}
	if failed {
		stop()
		os.RemoveAll(dir)
		os.Exit(1)
	}
}
