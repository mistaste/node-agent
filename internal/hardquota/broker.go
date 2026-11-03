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
	pendingMu                     sync.Mutex
	pending                       map[string]unusedReturn
	abandoned                     map[string]abandonedReturn
}

const firstBatch uint32 = 0
const maxBatch uint32 = 4 << 20
const maxCreditEntries = 4096

type cachedGrant struct {
	remaining uint32
	deadline  time.Time
	requestID string
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
	return &Broker{endpoint: strings.TrimRight(endpoint, "/") + "/v1/internal/node/traffic/reserve", secret: secret, token: token, boot: nonce(), credits: make(map[string]*credit), pending: make(map[string]unusedReturn), abandoned: make(map[string]abandonedReturn), client: &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("quota redirects forbidden") }}}, nil
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
	expired := expireCredit(c, now)
	b.returnUnused(ctx, id, expired)
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
		if batch < n {
			batch = n
		}
		part, e := b.reserve(ctx, id, batch)
		amount, deadline := part.remaining, part.deadline
		if e != nil {
			unused := c.parts
			c.parts = nil
			c.remaining = 0
			b.returnUnused(ctx, id, unused)
			c.deniedUntil = time.Now().Add(250 * time.Millisecond)
			return 0, e
		}
		if amount == 0 {
			c.deniedUntil = time.Now().Add(250 * time.Millisecond)
		}
		if amount > 0 {
			c.deniedUntil = time.Time{}
			c.parts = append(c.parts, part)
			c.remaining += amount
			c.deadline = deadline
			c.nextBatch = batch
			c.issued = time.Now()
		}
	}
	b.returnUnused(ctx, id, expireCredit(c, time.Now()))
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

func expireCredit(c *credit, now time.Time) []cachedGrant {
	var expired []cachedGrant
	kept := c.parts[:0]
	c.remaining = 0
	for _, part := range c.parts {
		if now.Before(part.deadline) {
			kept = append(kept, part)
			c.remaining += part.remaining
		} else if part.remaining > 0 {
			expired = append(expired, part)
		}
	}
	c.parts = kept
	return expired
}

type remoteGrant struct {
	RequestID         string    `json:"request_id"`
	BootID            string    `json:"boot_id"`
	ClientUUID        string    `json:"client_uuid"`
	Bytes             uint32    `json:"bytes"`
	ExpiresAt         time.Time `json:"expires_at"`
	ValidForMillis    int64     `json:"valid_for_ms"`
	SettlementVersion int       `json:"settlement_version"`
}

func (b *Broker) fetchReservation(ctx context.Context, id string, n uint32, requestID string) (remoteGrant, error, bool) {
	payload := struct {
		RequestID  string `json:"request_id"`
		BootID     string `json:"boot_id"`
		ClientUUID string `json:"client_uuid"`
		Bytes      uint32 `json:"bytes"`
		Atomic     bool   `json:"atomic"`
	}{requestID, b.boot, id, n, false}
	body, e := json.Marshal(payload)
	if e != nil {
		return remoteGrant{}, e, false
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint, bytes.NewReader(body))
	if e != nil {
		return remoteGrant{}, e, false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Secret", b.secret)
	req.Header.Set("X-Service-Token", b.token)
	response, e := b.client.Do(req)
	if e != nil {
		return remoteGrant{}, e, true
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return remoteGrant{}, ErrDenied, response.StatusCode >= 500
	}
	var grant remoteGrant
	if e = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&grant); e != nil {
		return grant, e, true
	}
	if grant.RequestID != requestID || grant.BootID != b.boot || grant.ClientUUID != id || grant.Bytes > n || grant.ExpiresAt.IsZero() {
		return grant, ErrDenied, true
	}
	return grant, nil, false
}
func (b *Broker) reserve(ctx context.Context, id string, n uint32) (cachedGrant, error) {
	b.pendingMu.Lock()
	full := len(b.pending)+len(b.abandoned) >= 8192
	b.pendingMu.Unlock()
	if full {
		return cachedGrant{}, ErrDenied
	}
	requestID := nonce()
	started := time.Now()
	uncertain := false
	for attempt := 0; attempt < 2; attempt++ {
		grant, e, maybeCharged := b.fetchReservation(ctx, id, n, requestID)
		uncertain = uncertain || maybeCharged
		if e == nil {
			deadline := started.Add(time.Duration(grant.ValidForMillis)*time.Millisecond - 100*time.Millisecond)
			if grant.SettlementVersion == 1 && grant.ValidForMillis > 100 && grant.ValidForMillis <= 5000 && time.Since(started) <= 2*time.Second && time.Now().Before(deadline) {
				return cachedGrant{remaining: grant.Bytes, deadline: deadline, requestID: requestID}, nil
			}
			// A complete but unusable grant was never handed to an engine.
			b.enqueueUnused(id, []cachedGrant{{remaining: grant.Bytes, requestID: requestID}})
			return cachedGrant{}, ErrDenied
		}
		if ctx.Err() != nil {
			break
		}
		if attempt == 0 {
			timer := time.NewTimer(25 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
		}
	}
	if uncertain {
		b.pendingMu.Lock()
		if len(b.pending)+len(b.abandoned) < 8192 {
			b.abandoned[requestID] = abandonedReturn{id, n}
		}
		b.pendingMu.Unlock()
	}
	return cachedGrant{}, ErrDenied
}

// Wire: UUID[36], direction[1], atomic[1], bytes[4]. Response: status[1],
// granted bytes[4]. EOF/timeouts/socket loss NEVER imply permission to forward.
func (b *Broker) Serve(ctx context.Context, l net.Listener) error {
	go func() { <-ctx.Done(); l.Close() }()
	sweepCtx, stopSweep := context.WithCancel(ctx)
	var active, maintenance sync.WaitGroup
	maintenance.Add(1)
	defer func() { stopSweep(); maintenance.Wait(); active.Wait() }()
	go func() {
		defer maintenance.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sweepCtx.Done():
				return
			case <-ticker.C:
				closeCtx, cancel := context.WithTimeout(sweepCtx, 2*time.Second)
				b.ReconcileExpired(closeCtx)
				cancel()
			}
		}
	}()
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
		active.Add(1)
		go func() {
			defer active.Done()
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

type abandonedReturn struct {
	id        string
	requested uint32
}

func (b *Broker) recoverAbandoned(ctx context.Context) {
	b.pendingMu.Lock()
	snapshot := make(map[string]abandonedReturn, len(b.abandoned))
	for key, value := range b.abandoned {
		snapshot[key] = value
	}
	b.pendingMu.Unlock()
	type recovery struct {
		requestID string
		value     abandonedReturn
	}
	jobs := make(chan recovery)
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobs {
				grant, e, _ := b.fetchReservation(ctx, job.value.id, job.value.requested, job.requestID)
				if e != nil {
					continue
				}
				b.enqueueUnused(job.value.id, []cachedGrant{{remaining: grant.Bytes, requestID: job.requestID}})
				b.pendingMu.Lock()
				delete(b.abandoned, job.requestID)
				b.pendingMu.Unlock()
			}
		}()
	}
	for key, value := range snapshot {
		select {
		case jobs <- recovery{key, value}:
		case <-ctx.Done():
		}
	}
	close(jobs)
	workers.Wait()
}

type unusedReturn struct {
	id   string
	part cachedGrant
}

func (b *Broker) enqueueUnused(id string, parts []cachedGrant) []unusedReturn {
	b.pendingMu.Lock()
	defer b.pendingMu.Unlock()
	var added []unusedReturn
	for _, part := range parts {
		if part.remaining == 0 || part.requestID == "" {
			continue
		}
		if len(b.pending) >= 8192 {
			continue
		}
		ticket := unusedReturn{id, part}
		b.pending[part.requestID] = ticket
		added = append(added, ticket)
	}
	return added
}
func (b *Broker) attemptReturn(ctx context.Context, ticket unusedReturn) {
	part := ticket.part
	body, _ := json.Marshal(struct {
		RequestID   string `json:"request_id"`
		BootID      string `json:"boot_id"`
		ClientUUID  string `json:"client_uuid"`
		UnusedBytes uint32 `json:"unused_bytes"`
	}{part.requestID, b.boot, ticket.id, part.remaining})
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(b.endpoint, "/reserve")+"/settle", bytes.NewReader(body))
	if e != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Secret", b.secret)
	req.Header.Set("X-Service-Token", b.token)
	response, e := b.client.Do(req)
	if e != nil {
		return
	}
	defer response.Body.Close()
	var ack struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
	}
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&ack) != nil || ack.RequestID != part.requestID || ack.Status != "closed" {
		return
	}
	b.pendingMu.Lock()
	delete(b.pending, part.requestID)
	b.pendingMu.Unlock()
}
func (b *Broker) returnUnused(ctx context.Context, id string, parts []cachedGrant) {
	for _, ticket := range b.enqueueUnused(id, parts) {
		b.attemptReturn(ctx, ticket)
	}
}
func (b *Broker) flushReturns(ctx context.Context) {
	b.pendingMu.Lock()
	tickets := make([]unusedReturn, 0, len(b.pending))
	for _, ticket := range b.pending {
		tickets = append(tickets, ticket)
	}
	b.pendingMu.Unlock()
	jobs := make(chan unusedReturn)
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for ticket := range jobs {
				b.attemptReturn(ctx, ticket)
			}
		}()
	}
	for _, ticket := range tickets {
		select {
		case jobs <- ticket:
		case <-ctx.Done():
		}
	}
	close(jobs)
	workers.Wait()
}
func (b *Broker) reconcileUnused(ctx context.Context, all bool) {
	b.mu.Lock()
	entries := make(map[string]*credit, len(b.credits))
	for id, c := range b.credits {
		entries[id] = c
	}
	b.mu.Unlock()
	for id, c := range entries {
		select {
		case <-c.gate:
			var parts []cachedGrant
			if all {
				parts = c.parts
				c.parts = nil
				c.remaining = 0
			} else {
				parts = expireCredit(c, time.Now())
			}
			c.gate <- struct{}{}
			b.enqueueUnused(id, parts)
		default:
		}
	}
	b.recoverAbandoned(ctx)
	b.flushReturns(ctx)
}

// ReconcileExpired returns only explicitly closed, known-unused credit. It
// retains immutable close requests after lost acknowledgements for safe retry.
func (b *Broker) ReconcileExpired(ctx context.Context) { b.reconcileUnused(ctx, false) }
func (b *Broker) ReleaseUnused(ctx context.Context) {
	b.reconcileUnused(ctx, true)
	for ctx.Err() == nil {
		b.pendingMu.Lock()
		left := len(b.pending) + len(b.abandoned)
		b.pendingMu.Unlock()
		if left == 0 {
			return
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		b.recoverAbandoned(ctx)
		b.flushReturns(ctx)
	}
}
