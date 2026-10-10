package trusttunnel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsClientRejectsNonLoopbackEndpoint(t *testing.T) {
	_, err := NewMetricsClient("https://example.com").Clients(context.Background())
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("error = %v, want loopback rejection", err)
	}
}

func TestMetricsClientParsesAndSanitizesClients(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/clients" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`[
			{"username":" AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE ","ip":"203.0.113.9","sessions":2,"inbound":12,"outbound":34},
			{"username":"bad","sessions":-1,"inbound":1,"outbound":2}
		]`))
	}))
	defer server.Close()

	client := NewMetricsClient(strings.Replace(server.URL, "localhost", "127.0.0.1", 1))
	clients, err := client.Clients(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].Username != "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" || clients[0].Inbound != 12 || clients[0].Outbound != 34 {
		t.Fatalf("clients = %+v", clients)
	}
}
