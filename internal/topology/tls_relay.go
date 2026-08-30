package topology

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxClientHelloBytes  = 64 << 10
	maxRelayConnections  = 2048
	tlsRelayInternalPort = 10443
)

// TLSRelay is a blind L4 router. It reads only the cleartext TLS ClientHello
// SNI, selects a controller-allowlisted fixed upstream, and then copies the
// original byte stream without terminating TLS or observing application data.
type TLSRelay struct {
	mu          sync.RWMutex
	targets     map[string]string
	ln          net.Listener
	sem         chan struct{}
	startedAt   time.Time
	accepted    uint64
	active      uint64
	completed   uint64
	failures    map[string]uint64
	targetStats map[string]*RelayTargetStats
	lastFailure *RelayFailure
	lastLogAt   map[string]time.Time
}

// RelayStats contains privacy-safe operational evidence for the blind relay.
// It never includes client addresses, credentials, traffic contents, URLs, or
// arbitrary destinations. Target names are restricted to the controller-owned
// SNI allowlist installed by Update.
type RelayStats struct {
	StartedAt   time.Time          `json:"started_at"`
	Accepted    uint64             `json:"accepted"`
	Active      uint64             `json:"active"`
	Completed   uint64             `json:"completed"`
	Failures    map[string]uint64  `json:"failures"`
	Targets     []RelayTargetStats `json:"targets,omitempty"`
	LastFailure *RelayFailure      `json:"last_failure,omitempty"`
}

type RelayTargetStats struct {
	ServerName       string            `json:"server_name"`
	Accepted         uint64            `json:"accepted"`
	Completed        uint64            `json:"completed"`
	BytesToUpstream  uint64            `json:"bytes_to_upstream"`
	BytesToClient    uint64            `json:"bytes_to_client"`
	UpstreamDialMs   uint64            `json:"upstream_dial_ms"`
	UpstreamDialRuns uint64            `json:"upstream_dial_runs"`
	Failures         map[string]uint64 `json:"failures"`
}

type RelayFailure struct {
	Code       string    `json:"code"`
	ServerName string    `json:"server_name,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

func NewTLSRelay() *TLSRelay {
	return &TLSRelay{
		targets: make(map[string]string), sem: make(chan struct{}, maxRelayConnections),
		startedAt: time.Now().UTC(), failures: make(map[string]uint64),
		targetStats: make(map[string]*RelayTargetStats), lastLogAt: make(map[string]time.Time),
	}
}

func (r *TLSRelay) Update(targets []RelayTarget) error {
	next := make(map[string]string, len(targets))
	for _, target := range targets {
		name := strings.ToLower(strings.TrimSpace(target.ServerName))
		next[name] = net.JoinHostPort(target.IngressAddress.String(), fmt.Sprintf("%d", target.IngressPort))
	}
	r.mu.Lock()
	r.targets = next
	for name := range next {
		if r.targetStats[name] == nil {
			r.targetStats[name] = &RelayTargetStats{ServerName: name, Failures: make(map[string]uint64)}
		}
	}
	if r.ln != nil {
		r.mu.Unlock()
		return nil
	}
	ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", tlsRelayInternalPort))
	if err != nil {
		r.mu.Unlock()
		return fmt.Errorf("listen blind TLS relay: %w", err)
	}
	r.ln = ln
	r.mu.Unlock()
	go r.serve(ln)
	return nil
}

func (r *TLSRelay) Close() error {
	r.mu.Lock()
	ln := r.ln
	r.ln = nil
	r.targets = make(map[string]string)
	r.mu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	return nil
}

func (r *TLSRelay) serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case r.sem <- struct{}{}:
			r.recordAccepted()
			go func() {
				defer func() {
					<-r.sem
					r.recordInactive()
				}()
				r.handle(conn)
			}()
		default:
			r.recordFailure("", "connection_limit")
			_ = conn.Close()
		}
	}
}

func (r *TLSRelay) handle(client net.Conn) {
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffered, serverName, err := readClientHello(client)
	if err != nil {
		code := "client_hello_invalid"
		if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
			code = "client_hello_timeout"
		}
		r.recordFailure("", code)
		return
	}
	serverName = strings.ToLower(serverName)
	r.mu.RLock()
	target := r.targets[serverName]
	r.mu.RUnlock()
	if target == "" {
		r.recordFailure("", "unknown_sni")
		return
	}
	r.recordTargetAccepted(serverName)
	dialStarted := time.Now()
	upstream, err := (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext(context.Background(), "tcp4", target)
	r.recordDial(serverName, time.Since(dialStarted))
	if err != nil {
		code := "upstream_dial_error"
		if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
			code = "upstream_dial_timeout"
		}
		r.recordFailure(serverName, code)
		return
	}
	defer upstream.Close()
	_ = client.SetDeadline(time.Time{})
	written, err := upstream.Write(buffered)
	r.recordBytes(serverName, uint64(written), 0)
	if err != nil {
		r.recordFailure(serverName, "upstream_initial_write")
		return
	}
	go func() {
		bytesCopied, copyErr := io.Copy(upstream, client)
		r.recordBytes(serverName, uint64(bytesCopied), 0)
		if copyErr != nil && !isExpectedRelayClose(copyErr) {
			r.recordFailure(serverName, "client_to_upstream_copy")
		}
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	bytesCopied, copyErr := io.Copy(client, upstream)
	r.recordBytes(serverName, 0, uint64(bytesCopied))
	if copyErr != nil && !isExpectedRelayClose(copyErr) {
		r.recordFailure(serverName, "upstream_to_client_copy")
		return
	}
	r.recordCompleted(serverName)
}

func isExpectedRelayClose(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF)
}

func (r *TLSRelay) recordAccepted() {
	r.mu.Lock()
	r.accepted++
	r.active++
	r.mu.Unlock()
}

func (r *TLSRelay) recordInactive() {
	r.mu.Lock()
	if r.active > 0 {
		r.active--
	}
	r.mu.Unlock()
}

func (r *TLSRelay) recordTargetAccepted(serverName string) {
	r.mu.Lock()
	if target := r.targetStats[serverName]; target != nil {
		target.Accepted++
	}
	r.mu.Unlock()
}

func (r *TLSRelay) recordDial(serverName string, elapsed time.Duration) {
	r.mu.Lock()
	if target := r.targetStats[serverName]; target != nil {
		target.UpstreamDialRuns++
		milliseconds := elapsed.Milliseconds()
		if milliseconds > 0 {
			target.UpstreamDialMs += uint64(milliseconds)
		}
	}
	r.mu.Unlock()
}

func (r *TLSRelay) recordBytes(serverName string, toUpstream, toClient uint64) {
	r.mu.Lock()
	if target := r.targetStats[serverName]; target != nil {
		target.BytesToUpstream += toUpstream
		target.BytesToClient += toClient
	}
	r.mu.Unlock()
}

func (r *TLSRelay) recordCompleted(serverName string) {
	r.mu.Lock()
	r.completed++
	if target := r.targetStats[serverName]; target != nil {
		target.Completed++
	}
	r.mu.Unlock()
}

func (r *TLSRelay) recordFailure(serverName, code string) {
	now := time.Now().UTC()
	r.mu.Lock()
	r.failures[code]++
	if target := r.targetStats[serverName]; target != nil {
		target.Failures[code]++
	}
	// Invalid ClientHello and unknown SNI are expected Internet scan noise on a
	// public 443 listener. Count them, but do not let them hide a real route
	// failure in the controller or admin UI.
	actionable := serverName != "" || code == "connection_limit"
	if actionable {
		r.lastFailure = &RelayFailure{Code: code, ServerName: serverName, OccurredAt: now}
	}
	logKey := code + ":" + serverName
	shouldLog := actionable && now.Sub(r.lastLogAt[logKey]) >= time.Minute
	if shouldLog {
		r.lastLogAt[logKey] = now
	}
	r.mu.Unlock()
	if shouldLog {
		log.Printf("[relay] connection failed code=%s target=%s", code, safeRelayLogTarget(serverName))
	}
}

func safeRelayLogTarget(serverName string) string {
	if serverName == "" {
		return "unclassified"
	}
	return serverName
}

// Snapshot returns an immutable copy suitable for the signed topology report.
func (r *TLSRelay) Snapshot() RelayStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := RelayStats{
		StartedAt: r.startedAt, Accepted: r.accepted, Active: r.active,
		Completed: r.completed, Failures: copyRelayCounts(r.failures),
	}
	for name := range r.targets {
		target := r.targetStats[name]
		if target == nil {
			continue
		}
		result.Targets = append(result.Targets, RelayTargetStats{
			ServerName: target.ServerName, Accepted: target.Accepted,
			Completed: target.Completed, BytesToUpstream: target.BytesToUpstream,
			BytesToClient: target.BytesToClient, UpstreamDialMs: target.UpstreamDialMs,
			UpstreamDialRuns: target.UpstreamDialRuns, Failures: copyRelayCounts(target.Failures),
		})
	}
	sort.Slice(result.Targets, func(i, j int) bool {
		return result.Targets[i].ServerName < result.Targets[j].ServerName
	})
	if r.lastFailure != nil {
		copy := *r.lastFailure
		result.LastFailure = &copy
	}
	return result
}

func copyRelayCounts(source map[string]uint64) map[string]uint64 {
	result := make(map[string]uint64, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func readClientHello(conn net.Conn) ([]byte, string, error) {
	raw := make([]byte, 0, 4096)
	handshake := make([]byte, 0, 4096)
	for len(raw) < maxClientHelloBytes {
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return nil, "", err
		}
		if header[0] != 22 {
			return nil, "", errors.New("first TLS record is not a handshake")
		}
		length := int(binary.BigEndian.Uint16(header[3:5]))
		if length < 1 || len(raw)+5+length > maxClientHelloBytes {
			return nil, "", errors.New("TLS ClientHello exceeds limit")
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, "", err
		}
		raw = append(raw, header...)
		raw = append(raw, payload...)
		handshake = append(handshake, payload...)
		if len(handshake) < 4 {
			continue
		}
		if handshake[0] != 1 {
			return nil, "", errors.New("TLS handshake is not ClientHello")
		}
		handshakeLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if handshakeLength < 1 || handshakeLength+4 > maxClientHelloBytes {
			return nil, "", errors.New("invalid TLS ClientHello length")
		}
		if len(handshake) >= handshakeLength+4 {
			name, err := clientHelloServerName(handshake[4 : handshakeLength+4])
			return raw, name, err
		}
	}
	return nil, "", errors.New("TLS ClientHello incomplete")
}

func clientHelloServerName(hello []byte) (string, error) {
	if len(hello) < 34 {
		return "", errors.New("short TLS ClientHello")
	}
	offset := 34
	if offset >= len(hello) {
		return "", errors.New("missing TLS session id")
	}
	offset += 1 + int(hello[offset])
	if offset+2 > len(hello) {
		return "", errors.New("missing TLS cipher suites")
	}
	offset += 2 + int(binary.BigEndian.Uint16(hello[offset:offset+2]))
	if offset >= len(hello) {
		return "", errors.New("missing TLS compression methods")
	}
	offset += 1 + int(hello[offset])
	if offset+2 > len(hello) {
		return "", errors.New("missing TLS extensions")
	}
	extensionsEnd := offset + 2 + int(binary.BigEndian.Uint16(hello[offset:offset+2]))
	offset += 2
	if extensionsEnd > len(hello) {
		return "", errors.New("invalid TLS extensions")
	}
	for offset+4 <= extensionsEnd {
		kind := binary.BigEndian.Uint16(hello[offset : offset+2])
		length := int(binary.BigEndian.Uint16(hello[offset+2 : offset+4]))
		offset += 4
		if offset+length > extensionsEnd {
			return "", errors.New("invalid TLS extension")
		}
		if kind == 0 {
			data := hello[offset : offset+length]
			if len(data) < 5 || int(binary.BigEndian.Uint16(data[:2]))+2 != len(data) || data[2] != 0 {
				return "", errors.New("invalid TLS SNI")
			}
			nameLength := int(binary.BigEndian.Uint16(data[3:5]))
			if nameLength < 1 || 5+nameLength > len(data) {
				return "", errors.New("invalid TLS SNI hostname")
			}
			name := strings.ToLower(string(data[5 : 5+nameLength]))
			if !hostnamePattern.MatchString(name) {
				return "", errors.New("TLS SNI hostname is not allowlist-compatible")
			}
			return name, nil
		}
		offset += length
	}
	return "", errors.New("TLS SNI missing")
}
