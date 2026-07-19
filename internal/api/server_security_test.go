package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardex/node-agent/internal/config"
)

func TestManagementAuthFailsClosedAndAcceptsOnlyExactBearer(t *testing.T) {
	secret := strings.Repeat("s", 32)
	hit := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusNoContent)
	})

	for _, testCase := range []struct {
		name       string
		configured string
		header     string
		want       int
	}{
		{name: "placeholder is unavailable", configured: "change-me-secret", header: "Bearer change-me-secret", want: http.StatusServiceUnavailable},
		{name: "missing", configured: secret, want: http.StatusUnauthorized},
		{name: "wrong scheme", configured: secret, header: "Basic " + secret, want: http.StatusUnauthorized},
		{name: "wrong token", configured: secret, header: "Bearer " + strings.Repeat("x", 32), want: http.StatusUnauthorized},
		{name: "exact bearer", configured: secret, header: "Bearer " + secret, want: http.StatusNoContent},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			hit = false
			server := &Server{cfg: &config.Config{Secret: testCase.configured}}
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			if testCase.header != "" {
				request.Header.Set("Authorization", testCase.header)
			}
			server.auth(next).ServeHTTP(recorder, request)
			if recorder.Code != testCase.want {
				t.Fatalf("status=%d, want %d", recorder.Code, testCase.want)
			}
			if hit != (testCase.want == http.StatusNoContent) {
				t.Fatalf("handler hit=%v", hit)
			}
		})
	}
}
