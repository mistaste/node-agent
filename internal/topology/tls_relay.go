package topology

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
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
	mu      sync.RWMutex
	targets map[string]string
	ln      net.Listener
	sem     chan struct{}
}

func NewTLSRelay() *TLSRelay {
	return &TLSRelay{targets: make(map[string]string), sem: make(chan struct{}, maxRelayConnections)}
}

func (r *TLSRelay) Update(targets []RelayTarget) error {
	next := make(map[string]string, len(targets))
	for _, target := range targets {
		name := strings.ToLower(strings.TrimSpace(target.ServerName))
		next[name] = net.JoinHostPort(target.IngressAddress.String(), fmt.Sprintf("%d", target.IngressPort))
	}
	r.mu.Lock()
	r.targets = next
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
			go func() {
				defer func() { <-r.sem }()
				r.handle(conn)
			}()
		default:
			_ = conn.Close()
		}
	}
}

func (r *TLSRelay) handle(client net.Conn) {
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffered, serverName, err := readClientHello(client)
	if err != nil {
		return
	}
	r.mu.RLock()
	target := r.targets[strings.ToLower(serverName)]
	r.mu.RUnlock()
	if target == "" {
		return
	}
	upstream, err := (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext(context.Background(), "tcp4", target)
	if err != nil {
		return
	}
	defer upstream.Close()
	_ = client.SetDeadline(time.Time{})
	if _, err = upstream.Write(buffered); err != nil {
		return
	}
	go func() {
		_, _ = io.Copy(upstream, client)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	_, _ = io.Copy(client, upstream)
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
