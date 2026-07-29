package trusttunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
)

type fakeProcess struct {
	running bool
	stops   int
	onStop  func()
}

func (p *fakeProcess) Stop(context.Context) error {
	p.running = false
	p.stops++
	if p.onStop != nil {
		p.onStop()
	}
	return nil
}
func (p *fakeProcess) Running() bool { return p.running }

type fakeStarter struct {
	starts int
	fail   bool
	last   *fakeProcess
	port   int
	ln     net.Listener
}

func (s *fakeStarter) Start(_ string, _ ...string) (endpointProcess, error) {
	s.starts++
	if s.fail {
		return nil, errors.New("start failed")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s.ln = ln
	s.port = ln.Addr().(*net.TCPAddr).Port
	s.last = &fakeProcess{running: true}
	return s.last, nil
}

func (s *fakeStarter) close() {
	if s.ln != nil {
		_ = s.ln.Close()
		s.ln = nil
	}
}

func testRuntime(t *testing.T, starter processStarter) *Runtime {
	t.Helper()
	root := t.TempDir()
	binary := filepath.Join(root, "trusttunnel_endpoint")
	if err := os.WriteFile(binary, []byte("binary"), 0700); err != nil {
		t.Fatal(err)
	}
	runtime, err := NewRuntime(root, binary, "ignored", "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	runtime.starter = starter
	return runtime
}

func requestForPort(port int) ApplyRequest {
	return ApplyRequest{
		InboundID: "catalog-trusttunnel", Tag: "gx-trusttunnel", Revision: 4,
		Endpoint:        Endpoint{Port: port, Hostname: "vpn.example.com", CertificateFile: "CERT_PATH", PrivateKeyFile: "KEY_PATH", ClientUUIDs: []string{"11111111-1111-4111-8111-111111111111"}, EnableHTTP2: true},
		ClientSetSHA256: "client-hash",
	}
}

func prepareRequest(t *testing.T, runtime *Runtime, starter *fakeStarter) ApplyRequest {
	t.Helper()
	// Reserve and release a port. fakeStarter rebinds its own random listener;
	// tests update the request after Start through a fixed listener below.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	request := requestForPort(port)
	request.Endpoint.CertificateFile = filepath.Join(runtime.root, "certs", "fullchain.pem")
	request.Endpoint.PrivateKeyFile = filepath.Join(runtime.root, "certs", "privkey.pem")
	// Start must listen on the requested port, so replace the starter with one
	// whose Start callback binds that exact port.
	starter.port = port
	return request
}

type fixedStarter struct {
	starts  int
	fail    bool
	process *fakeProcess
	ln      net.Listener
	port    int
}

func (s *fixedStarter) Start(_ string, _ ...string) (endpointProcess, error) {
	s.starts++
	if s.fail {
		return nil, errors.New("start failed")
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(s.port)))
	if err != nil {
		return nil, err
	}
	s.ln = ln
	s.process = &fakeProcess{running: true, onStop: func() { s.close() }}
	return s.process, nil
}
func (s *fixedStarter) close() {
	if s.ln != nil {
		_ = s.ln.Close()
		s.ln = nil
	}
}
func itoa(value int) string { return fmt.Sprintf("%d", value) }

func newFixedRuntime(t *testing.T) (*Runtime, *fixedStarter, ApplyRequest) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	starter := &fixedStarter{port: port}
	runtime := testRuntime(t, starter)
	request := requestForPort(port)
	request.Endpoint.CertificateFile = filepath.Join(runtime.root, "certs", "fullchain.pem")
	request.Endpoint.PrivateKeyFile = filepath.Join(runtime.root, "certs", "privkey.pem")
	return runtime, starter, request
}

func TestRuntimeAppliesAtomicBundleAndReportsState(t *testing.T) {
	runtime, starter, request := newFixedRuntime(t)
	defer starter.close()
	state, err := runtime.Apply(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if state.Revision != 4 || state.ClientCount != 1 || state.Digest == "" || starter.starts != 1 {
		t.Fatalf("unexpected state: %+v", state)
	}
	for _, name := range []string{"vpn.toml", "hosts.toml", "credentials.toml", "state.json"} {
		info, err := os.Stat(filepath.Join(runtime.root, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode = %o", name, info.Mode().Perm())
		}
	}
}

func TestRuntimeCloseStopsProcessAndKeepsDesiredState(t *testing.T) {
	runtime, starter, request := newFixedRuntime(t)
	defer starter.close()
	if _, err := runtime.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if starter.process == nil || starter.process.running || starter.process.stops != 1 {
		t.Fatalf("endpoint was not stopped on runtime close: %+v", starter.process)
	}
	if state, ok := runtime.State(); !ok || state.InboundID != request.InboundID {
		t.Fatalf("runtime close removed durable desired state: state=%+v ok=%v", state, ok)
	}
}

func TestRuntimeRollsBackFilesWhenStartFails(t *testing.T) {
	runtime, starter, request := newFixedRuntime(t)
	if _, err := runtime.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(runtime.root, "state.json"))
	starter.close()
	starter.fail = true
	request.Revision = 5
	request.Endpoint.EnableHTTP3 = true
	if _, err := runtime.Apply(context.Background(), request); err == nil {
		t.Fatal("expected start failure")
	}
	after, _ := os.ReadFile(filepath.Join(runtime.root, "state.json"))
	if string(after) != string(before) {
		t.Fatal("failed apply did not restore last-known-good state")
	}
}

func TestRuntimeDoesNotRestartUnchangedHealthyEndpoint(t *testing.T) {
	runtime, starter, request := newFixedRuntime(t)
	defer starter.close()
	if _, err := runtime.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if starter.starts != 1 {
		t.Fatalf("unchanged apply restarted endpoint %d times", starter.starts)
	}
}

func TestRuntimeRestartsAfterAgentProcessIsMissing(t *testing.T) {
	runtime, starter, request := newFixedRuntime(t)
	if _, err := runtime.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	starter.close()
	starter.process.running = false
	if _, err := runtime.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	defer starter.close()
	if starter.starts != 2 {
		t.Fatalf("missing endpoint was not restarted: %d", starter.starts)
	}
}

func TestRuntimeRemoveRequiresOwnershipAndStopsBeforeCleanup(t *testing.T) {
	runtime, starter, request := newFixedRuntime(t)
	defer starter.close()
	if _, err := runtime.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Remove(context.Background(), "other", 5); err == nil {
		t.Fatal("expected ownership rejection")
	}
	if err := runtime.Remove(context.Background(), request.InboundID, 5); err != nil {
		t.Fatal(err)
	}
	if _, ok := runtime.State(); ok {
		t.Fatal("state remains after delete")
	}
	if starter.process.stops != 1 {
		t.Fatalf("endpoint was not stopped: %d", starter.process.stops)
	}
}

func TestRuntimeRejectsOccupiedPortBeforeStartingEndpoint(t *testing.T) {
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	starter := &fixedStarter{port: listener.Addr().(*net.TCPAddr).Port}
	runtime := testRuntime(t, starter)
	request := requestForPort(starter.port)
	request.Endpoint.CertificateFile = filepath.Join(runtime.root, "certs", "fullchain.pem")
	request.Endpoint.PrivateKeyFile = filepath.Join(runtime.root, "certs", "privkey.pem")

	if _, err := runtime.Apply(context.Background(), request); err == nil {
		t.Fatal("expected occupied listener port to be rejected")
	}
	if starter.starts != 0 {
		t.Fatalf("endpoint started despite occupied port: %d", starter.starts)
	}
	if _, ok := runtime.State(); ok {
		t.Fatal("failed deployment persisted active state")
	}
}
