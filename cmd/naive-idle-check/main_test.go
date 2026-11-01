package main

import (
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAnHTTP200ThatClosesDuringIdleCannotPass(t *testing.T) {
	server := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		before := make([]byte, len("before-idle"))
		if _, err := io.ReadFull(r.Body, before); err != nil {
			return
		}
		w.Write(before)
		w.(http.Flusher).Flush()
		time.Sleep(20 * time.Millisecond)
		// End this stream while the client is quiet, reproducing the failure shape.
	}), &http2.Server{}))
	defer server.Close()
	result := runScenario(strings.TrimPrefix(server.URL, "http://"), "duplex_after_idle", 100*time.Millisecond)
	if result.Outcome != "fail" || result.Stage != "resume_bidirectional" {
		t.Fatalf("closed tunnel passed acceptance: %#v", result)
	}
}
