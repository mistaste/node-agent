package hardquota

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBrokerFailsClosedAndValidatesBindings(t *testing.T) {
	id := "00000000-0000-4000-8000-000000000001"
	for _, mode := range []string{"valid", "wrong_boot", "oversized", "expired", "denied", "atomic_partial"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Service-Token") != "token" || r.Header.Get("X-Node-Secret") != "01234567890123456789012345678901" {
					t.Error("missing authentication")
				}
				var body map[string]any
				json.NewDecoder(r.Body).Decode(&body)
				body["expires_at"] = time.Now().Add(time.Second)
				body["valid_for_ms"] = 1000
				switch mode {
				case "wrong_boot":
					body["boot_id"] = nonce()
				case "oversized":
					body["bytes"] = 99999
				case "expired":
					body["expires_at"] = time.Now().Add(-time.Second)
					body["valid_for_ms"] = 0
				case "denied":
					body["bytes"] = 0
				case "atomic_partial":
					body["bytes"] = 1
				}
				json.NewEncoder(w).Encode(body)
			}))
			defer server.Close()
			broker, e := New(server.URL, "01234567890123456789012345678901", "token")
			if e != nil {
				t.Fatal(e)
			}
			broker.client = server.Client()
			n, e := broker.Allocate(context.Background(), id, 10, mode == "atomic_partial")
			if mode == "valid" {
				if e != nil || n != 10 {
					t.Fatal(n, e)
				}
			} else if e == nil || n != 0 {
				t.Fatal("invalid grant accepted", n, e)
			}
			// Only already charged, unexpired credit can survive a controller outage.
			if c := broker.credits[id]; c != nil {
				for i := range c.parts {
					c.parts[i].deadline = time.Now().Add(-time.Second)
				}
			}
			server.Close()
			if n, e := broker.Allocate(context.Background(), id, 10, false); e == nil || n != 0 {
				t.Fatal("controller outage bypassed quota", n, e)
			}
		})
	}
}
func TestBrokerRestartChangesBootIdentity(t *testing.T) {
	a, _ := New("https://controller.invalid", "01234567890123456789012345678901", "token")
	b, _ := New("https://controller.invalid", "01234567890123456789012345678901", "token")
	if a.boot == b.boot {
		t.Fatal("boot identity reused")
	}
}

func TestBatchedCreditSharedAcrossTwoNodesAndConcurrentStreams(t *testing.T) {
	var mu sync.Mutex
	remaining := uint32(103)
	var charged atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			RequestID  string `json:"request_id"`
			BootID     string `json:"boot_id"`
			ClientUUID string `json:"client_uuid"`
			Bytes      uint32 `json:"bytes"`
		}
		json.NewDecoder(r.Body).Decode(&q)
		mu.Lock()
		grant := q.Bytes
		if grant > remaining {
			grant = remaining
		}
		remaining -= grant
		mu.Unlock()
		charged.Add(int64(grant))
		json.NewEncoder(w).Encode(map[string]any{"request_id": q.RequestID, "boot_id": q.BootID, "client_uuid": q.ClientUUID, "bytes": grant, "expires_at": time.Now().Add(5 * time.Second), "valid_for_ms": 5000})
	}))
	defer server.Close()
	nodes := make([]*Broker, 2)
	for i := range nodes {
		nodes[i], _ = New(server.URL, "01234567890123456789012345678901", "token")
		nodes[i].client = server.Client()
	}
	var forwarded atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			n, e := nodes[i%2].Allocate(context.Background(), "00000000-0000-4000-8000-000000000001", 17, false)
			if e == nil {
				forwarded.Add(int64(n))
			}
		}(i)
	}
	wg.Wait()
	if forwarded.Load() != 103 || charged.Load() != 103 {
		t.Fatal("global credit exceeded or stranded", forwarded.Load(), charged.Load())
	}
}

func TestBatchedCreditExpiryRestartLossAndAtomicBoundary(t *testing.T) {
	id := "00000000-0000-4000-8000-000000000001"
	var mu sync.Mutex
	remaining := uint32(200000)
	lost := false
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q map[string]any
		json.NewDecoder(r.Body).Decode(&q)
		mu.Lock()
		n := uint32(q["bytes"].(float64))
		if n > remaining {
			n = remaining
		}
		remaining -= n
		lose := lost
		mu.Unlock()
		calls.Add(1)
		if lose {
			http.Error(w, "synthetic lost charged response", 503)
			return
		}
		q["bytes"] = n
		q["expires_at"] = time.Now().Add(5 * time.Second)
		q["valid_for_ms"] = 5000
		json.NewEncoder(w).Encode(q)
	}))
	defer server.Close()
	makeBroker := func() *Broker {
		b, _ := New(server.URL, "01234567890123456789012345678901", "token")
		b.client = server.Client()
		return b
	}
	b := makeBroker()
	if n, e := b.Allocate(context.Background(), id, 1, false); n != 1 || e != nil {
		t.Fatal(n, e)
	}
	if n, e := b.Allocate(context.Background(), id, 1, false); n != 1 || e != nil || calls.Load() != 1 {
		t.Fatal("charged credit not reused", n, e, calls.Load())
	}
	c := b.credits[id]
	for i := range c.parts {
		c.parts[i].deadline = time.Now().Add(-time.Second)
	}
	c.deadline = time.Now().Add(-time.Second)
	if n, e := b.Allocate(context.Background(), id, 1, false); n != 1 || e != nil || calls.Load() != 2 {
		t.Fatal("expired credit reused", n, e, calls.Load())
	}
	restarted := makeBroker()
	if b.boot == restarted.boot {
		t.Fatal("reused boot")
	}
	if n, e := restarted.Allocate(context.Background(), id, 1, false); n != 1 || e != nil || calls.Load() != 3 {
		t.Fatal("restart restored credit", n, e, calls.Load())
	}
	mu.Lock()
	lost = true
	mu.Unlock()
	lostBroker := makeBroker()
	if n, e := lostBroker.Allocate(context.Background(), id, 1, false); n != 0 || e == nil {
		t.Fatal("lost response credited", n, e)
	}
	mu.Lock()
	lost = false
	remaining = 3
	mu.Unlock()
	atomicBroker := makeBroker()
	if n, e := atomicBroker.Allocate(context.Background(), id, 4, true); n != 0 || !errors.Is(e, ErrDenied) {
		t.Fatal("partial UDP forwarded", n, e)
	}
	// A valid zero refill must not destroy three already charged residual bytes.
	if n, e := atomicBroker.Allocate(context.Background(), id, 4, true); n != 0 || e == nil {
		t.Fatal("repeated partial UDP forwarded", n, e)
	}
	if n, e := atomicBroker.Allocate(context.Background(), id, 4, false); n != 3 || e != nil {
		t.Fatal("atomic denial lost TCP remainder", n, e)
	}
	if n, e := atomicBroker.Allocate(context.Background(), id, 1, false); n != 0 || e == nil {
		t.Fatal("credit resurrected", n, e)
	}
}

func TestCreditCannotExtendOriginalLeaseAndWaitIsCancellable(t *testing.T) {
	b, _ := New("https://controller.invalid", "01234567890123456789012345678901", "token")
	id := "00000000-0000-4000-8000-000000000001"
	c := b.creditFor(id)
	c.parts = []cachedGrant{{10, time.Now().Add(-time.Second)}, {20, time.Now().Add(time.Second)}}
	c.remaining = 30
	c.deadline = time.Now().Add(time.Second)
	if n, e := b.Allocate(context.Background(), id, 20, true); n != 20 || e != nil {
		t.Fatal("old lease merged into fresh credit", n, e)
	}
	<-c.gate
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, e := b.Allocate(ctx, id, 1, false); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("blocked client ignored cancellation", e)
	}
	c.gate <- struct{}{}
}

func TestOnlyPreviouslyChargedUnexpiredCreditSurvivesControllerOutage(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q map[string]any
		json.NewDecoder(r.Body).Decode(&q)
		q["expires_at"] = time.Now().Add(5 * time.Second)
		q["valid_for_ms"] = 5000
		json.NewEncoder(w).Encode(q)
	}))
	b, _ := New(server.URL, "01234567890123456789012345678901", "token")
	b.client = server.Client()
	id := "00000000-0000-4000-8000-000000000001"
	if n, e := b.Allocate(context.Background(), id, 1, false); n != 1 || e != nil {
		t.Fatal(n, e)
	}
	server.Close()
	if n, e := b.Allocate(context.Background(), id, 16384, false); n != 16384 || e != nil {
		t.Fatal("previously charged credit unavailable", n, e)
	}
	c := b.credits[id]
	for i := range c.parts {
		c.parts[i].deadline = time.Now().Add(-time.Second)
	}
	if n, e := b.Allocate(context.Background(), id, 1, false); n != 0 || e == nil {
		t.Fatal("expired credit became offline fallback", n, e)
	}
}

func TestServerLeaseTTLRejectsLegacyAndCannotUseNodeWallClock(t *testing.T) {
	for _, ttl := range []int64{0, 100, 5001, 1000} {
		t.Run(fmt.Sprint(ttl), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var q map[string]any
				json.NewDecoder(r.Body).Decode(&q)
				q["expires_at"] = time.Now().Add(-24 * time.Hour)
				q["valid_for_ms"] = ttl
				json.NewEncoder(w).Encode(q)
			}))
			defer server.Close()
			b, _ := New(server.URL, "01234567890123456789012345678901", "token")
			b.client = server.Client()
			id := "00000000-0000-4000-8000-000000000001"
			n, e := b.Allocate(context.Background(), id, 1, false)
			if ttl == 1000 {
				if e != nil || n != 1 {
					t.Fatal("wall clock skew changed server lease", n, e)
				}
				if time.Until(b.credits[id].parts[0].deadline) > 900*time.Millisecond {
					t.Fatal("remaining lease extended beyond RPC-start bound")
				}
			} else if e == nil || n != 0 {
				t.Fatal("missing/invalid remaining lease accepted", n, e)
			}
		})
	}
}
