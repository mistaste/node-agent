package topology

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRelayPreservesTLSAndBidirectionalHTTP2Payload(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			payload := bytes.Repeat([]byte{0x47}, 256*1024)
			backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil || !bytes.Equal(body, payload) || r.ProtoMajor != 2 {
					t.Errorf("upload corrupted: bytes=%d protocol=%s error=%v", len(body), r.Proto, err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				_, _ = w.Write(payload)
			}))
			backend.EnableHTTP2 = true
			backend.StartTLS()
			defer backend.Close()
			relay := NewTLSRelay()
			relay.targets["node.example.com"] = strings.TrimPrefix(backend.URL, "https://")
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					go relay.handle(conn)
				}
			}()
			transport := &http.Transport{
				ForceAttemptHTTP2: true,
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: "node.example.com", MinVersion: version, MaxVersion: version}, // Local httptest certificate only.
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp4", listener.Addr().String())
				},
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			response, err := client.Post("https://node.example.com/", "application/octet-stream", bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != 200 || response.ProtoMajor != 2 || !bytes.Equal(body, payload) {
				t.Fatalf("download corrupted: bytes=%d status=%d protocol=%s error=%v", len(body), response.StatusCode, response.Proto, err)
			}
		})
	}
}

func TestRelayRetriesOnlyClientHelloBeforeFirstServerByte(t *testing.T) {
	hello := []byte("synthetic parsed ClientHello")
	payload := []byte("application payload must not be replayed")
	var calls atomic.Int32
	firstRemainder := make(chan []byte, 1)
	secondPayload := make(chan []byte, 1)
	dial := func(context.Context, string) (net.Conn, error) {
		client, server := net.Pipe()
		attempt := calls.Add(1)
		go func() {
			defer server.Close()
			got := make([]byte, len(hello))
			if _, err := io.ReadFull(server, got); err != nil || string(got) != string(hello) {
				t.Errorf("ClientHello changed: %q, %v", got, err)
				return
			}
			if attempt == 1 {
				// Accept TCP and ClientHello but withhold the TLS response.
				rest, _ := io.ReadAll(server)
				firstRemainder <- rest
				return
			}
			_, _ = server.Write([]byte{0x16, 0x03, 0x03})
			got = make([]byte, len(payload))
			_, _ = io.ReadFull(server, got)
			secondPayload <- got
		}()
		return client, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, first, code := connectRelayUpstream(ctx, "fixed-target", hello, 100*time.Millisecond, dial, func(time.Duration) {})
	if code != "" || conn == nil || first != 0x16 {
		t.Fatalf("retry did not recover TLS opening: %q, first=%x", code, first)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	rest := make([]byte, 2)
	if _, err := io.ReadFull(conn, rest); err != nil || string(rest) != string([]byte{3, 3}) {
		t.Fatalf("server byte stream changed: %x, %v", rest, err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if got := <-firstRemainder; len(got) != 0 {
		t.Fatalf("application bytes reached abandoned attempt: %q", got)
	}
	if got := <-secondPayload; string(got) != string(payload) {
		t.Fatalf("application bytes changed: %q", got)
	}
	if calls.Load() != 2 {
		t.Fatalf("unexpected retry count: %d", calls.Load())
	}
}

func TestRelayHandshakeBlackholeHasBoundedAttemptsAndDeadline(t *testing.T) {
	var calls atomic.Int32
	dial := func(context.Context, string) (net.Conn, error) {
		client, server := net.Pipe()
		calls.Add(1)
		go func() { defer server.Close(); _, _ = io.Copy(io.Discard, server) }()
		return client, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	conn, _, code := connectRelayUpstream(ctx, "fixed-target", []byte("hello"), 30*time.Millisecond, dial, func(time.Duration) {})
	if conn != nil || code != "upstream_handshake_timeout" || calls.Load() != 2 {
		t.Fatalf("unexpected result: conn=%v code=%s attempts=%d", conn, code, calls.Load())
	}
	if time.Since(started) > time.Second {
		t.Fatal("handshake retries exceeded hard deadline")
	}
}

func TestRelayDoesNotRetryTLSAlertOrPostResponseClose(t *testing.T) {
	var calls atomic.Int32
	dial := func(context.Context, string) (net.Conn, error) {
		client, server := net.Pipe()
		calls.Add(1)
		go func() {
			defer server.Close()
			_, _ = io.CopyN(io.Discard, server, 5)
			_, _ = server.Write([]byte{0x15}) // TLS alert must reach the client.
		}()
		return client, nil
	}
	conn, first, code := connectRelayUpstream(context.Background(), "fixed-target", []byte("hello"), time.Second, dial, func(time.Duration) {})
	if conn == nil || code != "" || first != 0x15 {
		t.Fatalf("TLS alert was hidden: %s %x", code, first)
	}
	defer conn.Close()
	_, _ = io.ReadAll(conn)
	if calls.Load() != 1 {
		t.Fatal("retried after a server response")
	}
}

func TestRelayCancelledOpeningNeverDials(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, _, _ := connectRelayUpstream(ctx, "fixed-target", nil, time.Second,
		func(context.Context, string) (net.Conn, error) { t.Fatal("dial after cancellation"); return nil, nil }, func(time.Duration) {})
	if conn != nil {
		t.Fatal("connection returned after cancellation")
	}
}
