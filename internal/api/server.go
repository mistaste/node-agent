package api

import (
	"net/http"

	"github.com/guardex/node-agent/internal/config"
	"github.com/guardex/node-agent/internal/metrics"
	"github.com/guardex/node-agent/internal/xray"
)

type Server struct {
	cfg       *config.Config
	xray      *xray.Client
	collector *metrics.Collector
	mux       *http.ServeMux
}

func NewServer(cfg *config.Config, xrayClient *xray.Client, collector *metrics.Collector) *Server {
	s := &Server{
		cfg:       cfg,
		xray:      xrayClient,
		collector: collector,
		mux:       http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

func (s *Server) Run() error {
	return http.ListenAndServe(s.cfg.ListenAddr, s.auth(s.mux))
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		expected := "Bearer " + s.cfg.Secret
		if token != expected {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) registerRoutes() {
	h := &handlers{
		cfg:       s.cfg,
		xray:      s.xray,
		collector: s.collector,
	}

	s.mux.HandleFunc("GET /v1/health", h.health)
	s.mux.HandleFunc("GET /v1/metrics", h.getMetrics)

	s.mux.HandleFunc("POST /v1/users", h.addUser)
	s.mux.HandleFunc("DELETE /v1/users/{uuid}", h.removeUser)

	s.mux.HandleFunc("POST /v1/inbounds", h.addInbound)
	s.mux.HandleFunc("DELETE /v1/inbounds/{tag}", h.removeInbound)

	s.mux.HandleFunc("POST /v1/system/update-xray", h.updateXray)
	s.mux.HandleFunc("POST /v1/system/update-agent", h.updateAgent)
}
