package api

import (
	"log"
	"net/http"
	"regexp"
	"time"
)

var supportRequestID = regexp.MustCompile(`^[a-f0-9]{32}$`)

// Called inside auth. Never log the body, secret, query, node or user address.
func traceProvisioning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Guardex-Request-ID")
		operation := ""
		if r.Method == http.MethodPost {
			switch r.URL.Path {
			case "/v1/users":
				operation = "add_user"
			case "/v1/controller/reconcile":
				operation = "reconcile"
			}
		}
		if operation == "" || !supportRequestID.MatchString(id) {
			next.ServeHTTP(w, r)
			return
		}
		started := time.Now()
		log.Printf("provision_start request_id=%s operation=%s", id, operation)
		w.Header().Set("X-Guardex-Request-ID", id)
		defer func() {
			log.Printf("provision_finished request_id=%s operation=%s elapsed_ms=%d cancelled=%t", id, operation, time.Since(started).Milliseconds(), r.Context().Err() != nil)
		}()
		next.ServeHTTP(w, r)
	})
}
