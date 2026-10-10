package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProvisioningTracePreservesResponse(t *testing.T) {
	for _, id := range []string{"0123456789abcdef0123456789abcdef", "invalid-value", ""} {
		handler := traceProvisioning(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(409) }))
		req := httptest.NewRequest("POST", "/v1/controller/reconcile", nil)
		req.Header.Set("X-Guardex-Request-ID", id)
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		if out.Code != 409 {
			t.Fatal("changed status")
		}
		expected := ""
		if supportRequestID.MatchString(id) {
			expected = id
		}
		if out.Header().Get("X-Guardex-Request-ID") != expected {
			t.Fatal("unsafe or missing ID")
		}
	}
}
