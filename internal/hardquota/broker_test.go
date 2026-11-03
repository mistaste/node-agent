package hardquota

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
				switch mode {
				case "wrong_boot":
					body["boot_id"] = nonce()
				case "oversized":
					body["bytes"] = 99999
				case "expired":
					body["expires_at"] = time.Now().Add(-time.Second)
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
