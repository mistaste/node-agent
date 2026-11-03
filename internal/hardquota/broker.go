// Package hardquota provides a fail-closed, pre-forward byte allocation gate.
package hardquota

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrDenied = errors.New("traffic_quota_exhausted")

func nonce() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

type Broker struct {
	endpoint, secret, token, boot string
	client                        *http.Client
}

func New(endpoint, secret, token string) (*Broker, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(secret) < 32 || token == "" {
		return nil, errors.New("invalid quota controller configuration")
	}
	return &Broker{strings.TrimRight(endpoint, "/") + "/v1/internal/node/traffic/reserve", secret, token, nonce(), &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("quota redirects forbidden") }}}, nil
}

// Allocate uses a unique request for every forwarding operation. Central credit
// is charged permanently before returning; no local balance survives a restart
// and no network response can be replayed as fresh credit by this process.
func (b *Broker) Allocate(ctx context.Context, id string, n uint32, atomic bool) (uint32, error) {
	if n == 0 {
		return 0, nil
	}
	if n > 65536 {
		return 0, ErrDenied
	}
	requestID := nonce()
	payload := struct {
		RequestID  string `json:"request_id"`
		BootID     string `json:"boot_id"`
		ClientUUID string `json:"client_uuid"`
		Bytes      uint32 `json:"bytes"`
		Atomic     bool   `json:"atomic"`
	}{requestID, b.boot, id, n, atomic}
	body, e := json.Marshal(payload)
	if e != nil {
		return 0, e
	}
	started := time.Now()
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint, bytes.NewReader(body))
	if e != nil {
		return 0, e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Secret", b.secret)
	req.Header.Set("X-Service-Token", b.token)
	response, e := b.client.Do(req)
	if e != nil {
		return 0, e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return 0, ErrDenied
	}
	var grant struct {
		RequestID  string    `json:"request_id"`
		BootID     string    `json:"boot_id"`
		ClientUUID string    `json:"client_uuid"`
		Bytes      uint32    `json:"bytes"`
		ExpiresAt  time.Time `json:"expires_at"`
	}
	if e = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&grant); e != nil {
		return 0, e
	}
	if grant.RequestID != requestID || grant.BootID != b.boot || grant.ClientUUID != id || grant.Bytes > n || grant.Bytes == 0 || (atomic && grant.Bytes != n) || time.Since(started) > 2*time.Second || !grant.ExpiresAt.After(time.Now().Add(100*time.Millisecond)) {
		return 0, ErrDenied
	}
	return grant.Bytes, nil
}

// Wire: UUID[36], direction[1], atomic[1], bytes[4]. Response: status[1],
// granted bytes[4]. EOF/timeouts/socket loss NEVER imply permission to forward.
func (b *Broker) Serve(ctx context.Context, l net.Listener) error {
	go func() { <-ctx.Done(); l.Close() }()
	slots := make(chan struct{}, 128)
	for {
		c, e := l.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { <-slots }()
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			var frame [42]byte
			if _, e := io.ReadFull(c, frame[:]); e != nil {
				return
			}
			if frame[36] > 1 || frame[37] > 1 {
				return
			}
			n, e := b.Allocate(ctx, string(frame[:36]), binary.BigEndian.Uint32(frame[38:]), frame[37] == 1)
			var reply [5]byte
			if e == nil && n > 0 {
				reply[0] = 1
				binary.BigEndian.PutUint32(reply[1:], n)
			}
			c.Write(reply[:])
		}()
	}
}
