package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

type flow struct {
	body           io.ReadCloser
	writer         *io.PipeWriter
	cancel         context.CancelFunc
	closeTransport func() error
}

func (f *flow) close()       { f.cancel(); f.writer.Close(); f.body.Close(); f.closeTransport() }
func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func atom(path string, b []byte) error {
	if e := os.WriteFile(path+".next", b, 0600); e != nil {
		return e
	}
	return os.Rename(path+".next", path)
}
func wait(ctx context.Context, f func() bool) error {
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if f() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return fmt.Errorf("fixture condition timeout")
		case <-tick.C:
		}
	}
}

func open(ctx context.Context, proxy, target, user, password, version string) (*flow, int, error) {
	ctx, cancel := context.WithCancel(ctx)
	reader, writer := io.Pipe()
	req, e := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+proxy, reader)
	if e != nil {
		cancel()
		return nil, 0, e
	}
	req.Host = target
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+password)))
	config := &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"} // synthetic certificate, loopback-only fixture
	var transport http.RoundTripper
	var closeTransport func() error
	if version == "h2" {
		t := &http2.Transport{TLSClientConfig: config}
		transport = t
		closeTransport = func() error { t.CloseIdleConnections(); return nil }
	} else {
		t := &http3.Transport{TLSClientConfig: config}
		transport = t
		closeTransport = t.Close
	}
	type result struct {
		response *http.Response
		err      error
	}
	ch := make(chan result, 1)
	go func() { r, e := transport.RoundTrip(req); ch <- result{r, e} }()
	select {
	case r := <-ch:
		if r.err != nil {
			cancel()
			writer.Close()
			closeTransport()
			return nil, 0, r.err
		}
		if r.response.StatusCode != 200 {
			code := r.response.StatusCode
			r.response.Body.Close()
			cancel()
			writer.Close()
			closeTransport()
			return nil, code, nil
		}
		return &flow{r.response.Body, writer, cancel, closeTransport}, 200, nil
	case <-time.After(2 * time.Second):
		cancel()
		writer.Close()
		closeTransport()
		return nil, 0, fmt.Errorf("CONNECT timeout %s", version)
	}
}

func exchange(f *flow, udp *net.UDPAddr) error {
	payload := bytes.Repeat([]byte{0x47}, 4096)
	packet := payload
	if udp != nil {
		packet = make([]byte, 4+36+1+4+len(payload))
		binary.BigEndian.PutUint32(packet, uint32(len(packet)-4))
		copy(packet[4+12:], net.IPv4(127, 0, 0, 1).To4())
		binary.BigEndian.PutUint16(packet[4+16:], 1234)
		copy(packet[4+18+12:], udp.IP.To4())
		binary.BigEndian.PutUint16(packet[4+18+16:], uint16(udp.Port))
		packet[40] = 4
		copy(packet[41:], "test")
		copy(packet[45:], payload)
	}
	done := make(chan error, 1)
	go func() {
		if _, e := f.writer.Write(packet); e != nil {
			done <- e
			return
		}
		n := len(payload)
		if udp != nil {
			var header [4]byte
			if _, e := io.ReadFull(f.body, header[:]); e != nil {
				done <- e
				return
			}
			n = int(binary.BigEndian.Uint32(header[:]))
			if n < len(payload) || n > 65536 {
				done <- fmt.Errorf("invalid datagram response size %d", n)
				return
			}
		}
		b := make([]byte, n)
		_, e := io.ReadFull(f.body, b)
		if e == nil && !bytes.Equal(b[len(b)-len(payload):], payload) {
			e = fmt.Errorf("payload mismatch")
		}
		done <- e
	}()
	select {
	case e := <-done:
		return e
	case <-time.After(time.Second):
		return fmt.Errorf("payload timeout")
	}
}

func run() (map[string]any, error) {
	netem := os.Getenv("GUARDEX_HARD_QUOTA_NETEM") == "1"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root, e := os.MkdirTemp("/tmp", "guardex-quota-fixture-")
	if e != nil {
		return nil, e
	}
	defer os.RemoveAll(root)
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return nil, e
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		return nil, e
	}
	os.WriteFile(filepath.Join(root, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	os.WriteFile(filepath.Join(root, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600)
	reserve, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return nil, e
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	settings := fmt.Sprintf("listen_address=\"127.0.0.1:%d\"\nipv6_available=false\nallow_private_network_connections=true\ncredentials_file=\"%s/credentials.toml\"\ndefault_max_http2_conns_per_client=8\ndefault_max_http3_conns_per_client=8\n[listen_protocols.http1]\n[listen_protocols.http2]\n[listen_protocols.quic]\n", port, root)
	hosts := fmt.Sprintf("[[main_hosts]]\nhostname=\"localhost\"\ncert_chain_path=\"%s/cert.pem\"\nprivate_key_path=\"%s/key.pem\"\n", root, root)
	os.WriteFile(filepath.Join(root, "vpn.toml"), []byte(settings), 0600)
	os.WriteFile(filepath.Join(root, "hosts.toml"), []byte(hosts), 0600)

	user := "00000000-0000-4000-8000-000000000001"
	os.WriteFile(filepath.Join(root, "credentials.toml"), []byte(fmt.Sprintf("[[client]]\nusername=\"%s\"\npassword=\"fixture\"\n", user)), 0600)
	socket := filepath.Join(root, "quota.sock")
	broker, e := net.Listen("unix", socket)
	if e != nil {
		return nil, e
	}
	defer broker.Close()
	var mu sync.Mutex
	remaining := int64(103)
	var total atomic.Int64
	go func() {
		for {
			c, e := broker.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				var frame [42]byte
				if _, e := io.ReadFull(c, frame[:]); e != nil {
					return
				}
				n := int64(binary.BigEndian.Uint32(frame[38:]))
				mu.Lock()
				grant := n
				if grant > remaining {
					grant = remaining
				}
				if frame[37] == 1 && grant < n {
					grant = 0
				}
				remaining -= grant
				mu.Unlock()
				var reply [5]byte
				if grant > 0 {
					reply[0] = 1
					binary.BigEndian.PutUint32(reply[1:], uint32(grant))
					total.Add(grant)
				}
				c.Write(reply[:])
			}()
		}
	}()
	var logs bytes.Buffer
	cmd := exec.CommandContext(ctx, os.Getenv("GUARDEX_TT_HARD_TEST_BINARY"), filepath.Join(root, "vpn.toml"), filepath.Join(root, "hosts.toml"))
	cmd.Env = append(os.Environ(), "GUARDEX_HARD_QUOTA_REQUIRED=1", "GUARDEX_HARD_QUOTA_SOCKET="+socket)
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if e := cmd.Start(); e != nil {
		return nil, e
	}
	defer func() { cmd.Process.Signal(syscall.SIGTERM); cmd.Wait() }()
	proxy := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if e := wait(ctx, func() bool {
		c, e := net.DialTimeout("tcp", proxy, 10*time.Millisecond)
		if e == nil {
			c.Close()
			return true
		}
		return false
	}); e != nil {
		return nil, fmt.Errorf("endpoint not ready: %w log=%s", e, logs.String())
	}
	sink, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return nil, e
	}
	defer sink.Close()
	var forwarded, activeSink atomic.Int64
	go func() {
		for {
			c, e := sink.Accept()
			if e != nil {
				return
			}
			activeSink.Add(1)
			go func() {
				defer activeSink.Add(-1)
				defer c.Close()
				b := make([]byte, 65536)
				for {
					n, e := c.Read(b)
					forwarded.Add(int64(n))
					if e != nil {
						return
					}
				}
			}()
		}
	}()
	var wg sync.WaitGroup
	errors := make(chan error, 2)
	for _, v := range []string{"h2", "h3"} {
		wg.Add(1)
		go func(v string) {
			defer wg.Done()
			f, status, e := open(ctx, proxy, sink.Addr().String(), user, "fixture", v)
			if e != nil || status != 200 {
				errors <- fmt.Errorf("open %s status=%d: %v", v, status, e)
				return
			}
			defer f.close()
			go func() { f.writer.Write(bytes.Repeat([]byte("x"), 4096)) }()
			io.Copy(io.Discard, f.body)
		}(v)
	}
	wg.Wait()
	close(errors)
	for e := range errors {
		if e != nil {
			return nil, e
		}
	}
	deadline := time.Now().Add(time.Second)
	for forwarded.Load() < 103 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if total.Load() != 103 || forwarded.Load() > 103 || (!netem && forwarded.Load() != 103) || forwarded.Load() == 0 {
		return nil, fmt.Errorf("shared H2/H3 TCP boundary forwarded=%d allocated=%d want103", forwarded.Load(), total.Load())
	}

	push, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return nil, e
	}
	defer push.Close()
	go func() {
		for {
			c, e := push.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); c.Write(bytes.Repeat([]byte("d"), 4096)) }()
		}
	}()
	mu.Lock()
	remaining = 103
	mu.Unlock()
	var received atomic.Int64
	downloadErrors := make(chan error, 2)
	for _, v := range []string{"h2", "h3"} {
		wg.Add(1)
		go func(v string) {
			defer wg.Done()
			f, status, e := open(ctx, proxy, push.Addr().String(), user, "fixture", v)
			if e != nil || status != 200 {
				downloadErrors <- fmt.Errorf("download open %s %d %v", v, status, e)
				return
			}
			defer f.close()
			payload, _ := io.ReadAll(f.body)
			received.Add(int64(len(payload)))
		}(v)
	}
	wg.Wait()
	close(downloadErrors)
	for e := range downloadErrors {
		return nil, e
	}
	if received.Load() > 103 || (!netem && received.Load() != 103) || received.Load() == 0 {
		return nil, fmt.Errorf("shared H2/H3 TCP download boundary=%d want103", received.Load())
	}
	udp, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		return nil, e
	}
	defer udp.Close()
	var datagrams atomic.Int64
	go func() {
		b := make([]byte, 65536)
		for {
			n, a, e := udp.ReadFromUDP(b)
			if e != nil {
				return
			}
			datagrams.Add(1)
			udp.WriteToUDP(b[:n], a)
		}
	}()
	for _, v := range []string{"h2", "h3"} {
		beforeDatagrams := datagrams.Load()
		mu.Lock()
		remaining = 100
		mu.Unlock()
		f, status, e := open(ctx, proxy, "_udp2", user, "fixture", v)
		if e != nil || status != 200 {
			return nil, fmt.Errorf("UDP open %s %d %v", v, status, e)
		}
		if e := exchange(f, udp.LocalAddr().(*net.UDPAddr)); e == nil {
			f.close()
			return nil, fmt.Errorf("oversized datagram passed %s", v)
		}
		f.close()
		if datagrams.Load() != beforeDatagrams {
			return nil, fmt.Errorf("partial datagram forwarded")
		}
		mu.Lock()
		r := remaining
		mu.Unlock()
		if r != 100 {
			return nil, fmt.Errorf("denied UDP consumed partial grant %d", r)
		}
		mu.Lock()
		positiveBudget := int64(8192)
		attempts := 1
		if netem {
			positiveBudget = 32768
			attempts = 3
		}
		remaining = positiveBudget
		mu.Unlock()
		var positiveErr error
		for attempt := 0; attempt < attempts; attempt++ {
			f, status, e = open(ctx, proxy, "_udp2", user, "fixture", v)
			if e != nil || status != 200 {
				return nil, fmt.Errorf("positive UDP open %s %d %v", v, status, e)
			}
			positiveErr = exchange(f, udp.LocalAddr().(*net.UDPAddr))
			f.close()
			if positiveErr == nil {
				break
			}
		}
		if positiveErr != nil {
			return nil, fmt.Errorf("positive UDP %s: %v", v, positiveErr)
		}

		mu.Lock()
		r = remaining
		mu.Unlock()
		if (!netem && r != 0) || r < 0 || r > positiveBudget-8192 {
			return nil, fmt.Errorf("UDP directions not shared: %d", r)
		}
	}

	if e := wait(ctx, func() bool { return activeSink.Load() == 0 }); e != nil {
		return nil, fmt.Errorf("previous TCP flows did not drain: %w", e)
	}
	broker.Close()
	before := forwarded.Load()
	for _, v := range []string{"h2", "h3"} {
		f, status, e := open(ctx, proxy, sink.Addr().String(), user, "fixture", v)
		if e != nil || status != 200 {
			return nil, fmt.Errorf("outage open %s %d %v", v, status, e)
		}
		go func() { f.writer.Write([]byte("forbidden")) }()
		io.Copy(io.Discard, f.body)
		f.close()
	}
	if forwarded.Load() != before {
		return nil, fmt.Errorf("broker loss forwarded payload")
	}
	return map[string]any{"result": "PASS", "network_loss_mode": netem, "tcp_authorized_bytes": 103, "tcp_sink_forwarded_bytes": forwarded.Load(), "tcp_download_received_bytes": received.Load(), "tcp_upload_delivery_cost": 103 - forwarded.Load(), "tcp_download_delivery_cost": 103 - received.Load(), "h2_h3_udp_atomic_denied": true, "h2_h3_udp_both_directions": true, "broker_loss_failclosed": true}, nil
}
func main() {
	start := time.Now()
	result, e := run()
	if e != nil {
		result = map[string]any{"result": "FAIL", "error": e.Error()}
	}
	result["elapsed_ms"] = time.Since(start).Milliseconds()
	json.NewEncoder(os.Stdout).Encode(result)
	if e != nil {
		os.Exit(1)
	}
}
