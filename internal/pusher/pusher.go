package pusher

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/guardex/node-agent/internal/config"
	"github.com/guardex/node-agent/internal/metrics"
)

// Pusher periodically sends collected metrics to the Central Controller.
type Pusher struct {
	cfg       *config.Config
	collector *metrics.Collector
	http      *http.Client
}

func NewPusher(cfg *config.Config, collector *metrics.Collector) *Pusher {
	return &Pusher{
		cfg:       cfg,
		collector: collector,
		http: &http.Client{
			Timeout: 8 * time.Second,
			// The controller is reached on a non-standard port (:2096) that
			// Cloudflare does not proxy, so the node hits the origin's self-signed
			// cert directly — same as install.sh's `curl -k`. Auth is enforced by
			// the X-Service-Token header, not TLS trust.
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
		},
	}
}

// Run starts the push loop. Blocks until ctx is cancelled.
//
// The node identifies itself to the controller by its node_secret (AGENT_SECRET),
// so no per-node ID has to be configured — every node that registered auto-pushes.
func (p *Pusher) Run(ctx context.Context) {
	if p.cfg.ControllerURL == "" || p.cfg.InternalServiceToken == "" || p.cfg.Secret == "" {
		log.Println("[pusher] CONTROLLER_URL / INTERNAL_SERVICE_TOKEN / AGENT_SECRET not set — metrics push disabled")
		return
	}

	ticker := time.NewTicker(p.cfg.MetricsInterval)
	defer ticker.Stop()
	log.Printf("[pusher] started, pushing to %s every %s", p.cfg.ControllerURL, p.cfg.MetricsInterval)

	for {
		select {
		case <-ticker.C:
			if err := p.push(ctx); err != nil {
				log.Printf("[pusher] push error: %v", err)
			}
		case <-ctx.Done():
			log.Println("[pusher] stopped")
			return
		}
	}
}

type metricsPayload struct {
	NodeSecret   string  `json:"node_secret"`
	CPUPercent   float64 `json:"cpu_percent"`
	RAMPercent   float64 `json:"ram_percent"`
	NetBytesSent uint64  `json:"net_bytes_sent"`
	NetBytesRecv uint64  `json:"net_bytes_recv"`
	Sessions     int     `json:"sessions"`
}

func (p *Pusher) push(ctx context.Context) error {
	snap := p.collector.Latest()
	if snap == nil {
		return nil
	}

	payload := metricsPayload{
		NodeSecret:   p.cfg.Secret,
		CPUPercent:   snap.CPUPercent,
		RAMPercent:   snap.MemPercent,
		NetBytesSent: snap.NetBytesSent,
		NetBytesRecv: snap.NetBytesRecv,
		Sessions:     snap.ActiveUsers,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	url := fmt.Sprintf("%s/v1/internal/node/metrics", p.cfg.ControllerURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Service-Token", p.cfg.InternalServiceToken)

	resp, err := p.http.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("controller returned %d", resp.StatusCode)
	}
	return nil
}
