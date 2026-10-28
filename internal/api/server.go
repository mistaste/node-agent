package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/guardex/node-agent/internal/config"
	"github.com/guardex/node-agent/internal/metrics"
)

type Server struct {
	cfg        *config.Config
	collector  *metrics.Collector
	reconciler desiredStateReconciler
	mux        *http.ServeMux
}

func NewServer(cfg *config.Config, collector *metrics.Collector, reconciler desiredStateReconciler) *Server {
	s := &Server{cfg: cfg, collector: collector, reconciler: reconciler, mux: http.NewServeMux()}
	s.registerRoutes()
	return s
}

func (s *Server) Run() error {
	server := &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           s.auth(traceProvisioning(s.mux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if s.cfg.TLSCertFile != "" || s.cfg.TLSKeyFile != "" {
		if s.cfg.TLSCertFile == "" || s.cfg.TLSKeyFile == "" {
			return fmt.Errorf("both management TLS certificate and key are required")
		}
		return server.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
	}
	host, _, err := net.SplitHostPort(s.cfg.ListenAddr)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("management listener requires TLS outside loopback")
	}
	return server.ListenAndServe()
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.AgentAPISecretValid() {
			http.Error(w, `{"error":"management API unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		providedHash := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		expectedHash := sha256.Sum256([]byte("Bearer " + s.cfg.Secret))
		if subtle.ConstantTimeCompare(providedHash[:], expectedHash[:]) != 1 {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) registerRoutes() {
	h := &handlers{cfg: s.cfg, collector: s.collector, reconciler: s.reconciler}
	s.mux.HandleFunc("GET /v1/health", h.health)
	s.mux.HandleFunc("GET /v1/metrics", h.getMetrics)
	s.mux.HandleFunc("POST /v1/system/update-agent", h.updateAgent)
	if !s.cfg.MetricsOnly {
		s.mux.HandleFunc("POST /v1/controller/reconcile", h.reconcileDesiredState)
		s.mux.HandleFunc("POST /v1/users", h.nativeUserChange)
		s.mux.HandleFunc("DELETE /v1/users/{uuid}", h.nativeUserChange)
		s.mux.HandleFunc("POST /v1/system/restart", h.restartNode)
	}
}

func NewMetricsOnlyServer(cfg *config.Config, collector *metrics.Collector) *Server {
	cfg.MetricsOnly = true
	return NewServer(cfg, collector, nil)
}
