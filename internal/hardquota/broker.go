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
	"sync"
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
	mu                            sync.Mutex
	credits                       map[string]*credit
}

const firstBatch uint32 = 64 << 10
const maxBatch uint32 = 4 << 20
const maxCreditEntries = 4096

type cachedGrant struct {
	remaining uint32
	deadline  time.Time
}
type credit struct {
	deniedUntil time.Time
	parts       []cachedGrant
	gate        chan struct{}
	remaining   uint32
	nextBatch   uint32
	deadline    time.Time
	issued      time.Time
}

func (b *Broker) creditFor(id string) *credit {
	b.mu.Lock()
	defer b.mu.Unlock()
	if c := b.credits[id]; c != nil {
		return c
	}
	if len(b.credits) >= maxCreditEntries {
		for key, c := range b.credits {
			select {
			case <-c.gate:
				expired := !time.Now().Before(c.deadline)
				c.gate <- struct{}{}
				if expired {
					delete(b.credits, key)
				}
			default:
			}
		}
		if len(b.credits) >= maxCreditEntries {
			return nil
		}
	}
	c := &credit{gate: make(chan struct{}, 1), nextBatch: firstBatch}
	c.gate <- struct{}{}
	b.credits[id] = c
	return c
}

func New(endpoint, secret, token string) (*Broker, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(secret) < 32 || token == "" {
		return nil, errors.New("invalid quota controller configuration")
	}
	return &Broker{endpoint: strings.TrimRight(endpoint, "/") + "/v1/internal/node/traffic/reserve", secret: secret, token: token, boot: nonce(), credits: make(map[string]*credit), client: &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("quota redirects forbidden") }}}, nil
}

// Allocate spends only already charged credit, shared by all streams and both
// directions of this credential. Credit is memory-only and expires no later than
// its original five-second lease. Lost replies, expiry and restart burn credit.
func (b *Broker) Allocate(ctx context.Context, id string, n uint32, atomic bool) (uint32, error) {
	if n == 0 {
		return 0, nil
	}
	if n > 65536 || len(id) != 36 {
		return 0, ErrDenied
	}
	for i, ch := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if ch != '-' {
				return 0, ErrDenied
			}
			continue
		}
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return 0, ErrDenied
		}
	}
	id = strings.ToLower(id)
	c := b.creditFor(id)
	if c == nil {
		return 0, ErrDenied
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-c.gate:
	}
	defer func() { c.gate <- struct{}{} }()
	if e := ctx.Err(); e != nil {
		return 0, e
	}
	now := time.Now()
	expireCredit(c, now)
	if !now.Before(c.deadline) {
		c.nextBatch = firstBatch
	}
	if c.remaining < n && !now.Before(c.deniedUntil) {
		batch := c.nextBatch
		if !c.issued.IsZero() && now.Before(c.deadline) && now.Sub(c.issued) < 2*time.Second {
			batch *= 2
			if batch > maxBatch {
				batch = maxBatch
			}
		}
		amount, deadline, e := b.reserve(ctx, id, batch)
		if e != nil {
			c.remaining = 0
			c.parts = nil
			c.deniedUntil = time.Now().Add(250 * time.Millisecond)
			return 0, e
		}
		if amount == 0 {
			c.deniedUntil = time.Now().Add(250 * time.Millisecond)
		}
		if amount > 0 {
			c.deniedUntil = time.Time{}
			c.parts = append(c.parts, cachedGrant{amount, deadline})
			c.remaining += amount
			c.deadline = deadline
			c.nextBatch = batch
			c.issued = time.Now()
		}
	}
	expireCredit(c, time.Now())
	granted := n
	if granted > c.remaining {
		granted = c.remaining
	}
	if granted == 0 || (atomic && granted < n) {
		return 0, ErrDenied
	}
	c.remaining -= granted
	left := granted
	for left > 0 {
		part := &c.parts[0]
		take := left
		if take > part.remaining {
			take = part.remaining
		}
		part.remaining -= take
		left -= take
		if part.remaining == 0 {
			c.parts = c.parts[1:]
		}
	}
	return granted, nil
}

func expireCredit(c *credit, now time.Time) {
	kept := c.parts[:0]
	c.remaining = 0
	for _, part := range c.parts {
		if now.Before(part.deadline) {
			kept = append(kept, part)
			c.remaining += part.remaining
		}
	}
	c.parts = kept
}

func (b *Broker) reserve(ctx context.Context, id string, n uint32) (uint32, time.Time, error) {
	requestID := nonce()
	payload := struct {
		RequestID  string `json:"request_id"`
		BootID     string `json:"boot_id"`
		ClientUUID string `json:"client_uuid"`
		Bytes      uint32 `json:"bytes"`
		Atomic     bool   `json:"atomic"`
	}{requestID, b.boot, id, n, false}
	body, e := json.Marshal(payload)
	if e != nil {
		return 0, time.Time{}, e
	}
	started := time.Now()
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint, bytes.NewReader(body))
	if e != nil {
		return 0, time.Time{}, e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Secret", b.secret)
	req.Header.Set("X-Service-Token", b.token)
	response, e := b.client.Do(req)
	if e != nil {
		return 0, time.Time{}, e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return 0, time.Time{}, ErrDenied
	}
	var grant struct {
		RequestID      string    `json:"request_id"`
		BootID         string    `json:"boot_id"`
		ClientUUID     string    `json:"client_uuid"`
		Bytes          uint32    `json:"bytes"`
		ExpiresAt      time.Time `json:"expires_at"`
		ValidForMillis int64     `json:"valid_for_ms"`
	}
	if e = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&grant); e != nil {
		return 0, time.Time{}, e
	}
	if grant.RequestID != requestID || grant.BootID != b.boot || grant.ClientUUID != id || grant.Bytes > n || time.Since(started) > 2*time.Second || grant.ExpiresAt.IsZero() || grant.ValidForMillis <= 100 || grant.ValidForMillis > 5000 {
		return 0, time.Time{}, ErrDenied
	}
	// Anchor the server's remaining TTL before the RPC. The backend recomputes
	// it on retries, so expiry/month/Premium boundaries do not depend on node wall
	// clock skew and a replay cannot extend an original reservation.
	deadline := started.Add(time.Duration(grant.ValidForMillis)*time.Millisecond - 100*time.Millisecond)
	if !time.Now().Before(deadline) {
		return 0, time.Time{}, ErrDenied
	}
	return grant.Bytes, deadline, nil
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
			requestCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			n, e := b.Allocate(requestCtx, string(frame[:36]), binary.BigEndian.Uint32(frame[38:]), frame[37] == 1)
			var reply [5]byte
			if e == nil && n > 0 {
				reply[0] = 1
				binary.BigEndian.PutUint32(reply[1:], n)
			}
			c.Write(reply[:])
		}()
	}
}
