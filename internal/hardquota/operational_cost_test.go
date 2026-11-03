package hardquota

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Finite opt-in operational cost fixture: 17 credentials, 4,129 payload bytes,
// one five-second pause. Its ledger never refunds on elapsed time alone.
func TestOperationalPausedCreditCost(t *testing.T) {
	if os.Getenv("GUARDEX_QUOTA_OPERATIONAL_CANARY") != "1" {
		t.Skip("bounded operational canary")
	}
	type lease struct {
		amount, returned uint32
		closed           bool
	}
	var mu sync.Mutex
	grants := map[string]lease{}
	var charged, returned, forwarded uint64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			RequestID  string `json:"request_id"`
			BootID     string `json:"boot_id"`
			ClientUUID string `json:"client_uuid"`
			Bytes      uint32 `json:"bytes"`
			Unused     uint32 `json:"unused_bytes"`
		}
		if json.NewDecoder(r.Body).Decode(&q) != nil {
			http.Error(w, "bad", 400)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/settle") {
			g, ok := grants[q.RequestID]
			if !ok || q.Unused > g.amount || (g.closed && g.returned != q.Unused) {
				http.Error(w, "bad close", 403)
				return
			}
			if !g.closed {
				g.closed = true
				g.returned = q.Unused
				returned += uint64(q.Unused)
				grants[q.RequestID] = g
			}
			json.NewEncoder(w).Encode(map[string]any{"request_id": q.RequestID, "status": "closed"})
			return
		}
		charged += uint64(q.Bytes)
		grants[q.RequestID] = lease{amount: q.Bytes}
		json.NewEncoder(w).Encode(map[string]any{"request_id": q.RequestID, "boot_id": q.BootID, "client_uuid": q.ClientUUID, "bytes": q.Bytes, "expires_at": time.Now().Add(5 * time.Second), "valid_for_ms": 5000, "settlement_version": 1})
	}))
	defer server.Close()
	b, _ := New(server.URL, "01234567890123456789012345678901", "token")
	b.client = server.Client()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	send := func(id string, n uint32) {
		t.Helper()
		got, e := b.Allocate(ctx, id, n, false)
		if e != nil || got != n {
			t.Fatal(got, e)
		}
		forwarded += uint64(got)
	}
	for i := 1; i <= 16; i++ {
		send(fmt.Sprintf("00000000-0000-4000-8000-%012d", i), 1)
	}
	burst := "00000000-0000-4000-8000-999999999999"
	for i := 0; i < 64; i++ {
		send(burst, 64)
	}
	mu.Lock()
	t.Logf("before_pause forwarded=%d charged=%d returned=%d net_excess=%d", forwarded, charged, returned, charged-returned-forwarded)
	mu.Unlock()
	time.Sleep(5200 * time.Millisecond)
	for i := 1; i <= 16; i++ {
		send(fmt.Sprintf("00000000-0000-4000-8000-%012d", i), 1)
	}
	send(burst, 1)
	mu.Lock()
	defer mu.Unlock()
	excess := charged - returned - forwarded
	t.Logf("after_pause forwarded=%d charged=%d returned=%d net_excess=%d", forwarded, charged, returned, excess)
	if os.Getenv("GUARDEX_QUOTA_EXPECT_BASELINE") != "1" && excess != 0 {
		t.Fatalf("material paused-credit overcharge: %d", excess)
	}
}
