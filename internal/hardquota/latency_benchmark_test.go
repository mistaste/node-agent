package hardquota

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// Opt-in real TLS RPC benchmark with deterministic injected controller delay.
// It measures the quota path alone, not end-to-end production VPN throughput.
func TestControllerRTTBenchmark(t *testing.T) {
	if os.Getenv("GUARDEX_QUOTA_LATENCY_BENCH") != "1" {
		t.Skip("opt-in isolated latency benchmark")
	}
	for _, delay := range []time.Duration{0, 25 * time.Millisecond, 100 * time.Millisecond, 250 * time.Millisecond} {
		for _, total := range []int{1 << 20, 16 << 20} {
			var calls atomic.Int64
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(delay)
				calls.Add(1)
				var body map[string]any
				json.NewDecoder(r.Body).Decode(&body)
				body["expires_at"] = time.Now().Add(5 * time.Second)
				body["valid_for_ms"] = 5000
				json.NewEncoder(w).Encode(body)
			}))
			b, e := New(server.URL, "01234567890123456789012345678901", "token")
			if e != nil {
				t.Fatal(e)
			}
			b.client = server.Client()
			start := time.Now()
			for used := 0; used < total; used += 16384 {
				if n, e := b.Allocate(context.Background(), "00000000-0000-4000-8000-000000000001", 16384, false); e != nil || n != 16384 {
					t.Fatal(n, e)
				}
			}
			seconds := time.Since(start).Seconds()
			server.Close()
			t.Logf("quota_path delay_ms=%d payload_MiB=%d RPCs=%d RPCs_per_MiB=%.3f elapsed_s=%.3f throughput_Mbps=%.2f", delay.Milliseconds(), total/(1<<20), calls.Load(), float64(calls.Load())/float64(total/(1<<20)), seconds, float64(total)*8/seconds/1e6)
		}
	}
}
