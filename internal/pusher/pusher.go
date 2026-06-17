package pusher

import (
	"bytes"
	"context"
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
		http:      &http.Client{Timeout: 8 * time.Second},
	}
}

// Run starts the push loop. Blocks until ctx is cancelled.
func (p *Pusher) Run(ctx context.Context) {
	if p.cfg.ControllerURL == "" || p.cfg.NodeID == "" {
		log.Println("[pusher] CONTROLLER_URL or NODE_ID not set — metrics push disabled")
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
		CPUPercent:   snap.CPUPercent,
		RAMPercent:   snap.MemPercent,
		NetBytesSent: snap.NetBytesSent,
		NetBytesRecv: snap.NetBytesRecv,
		Sessions:     len(snap.UserTraffic),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	url := fmt.Sprintf("%s/v1/nodes/%s/metrics", p.cfg.ControllerURL, p.cfg.NodeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Service-Token", p.cfg.Secret)

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
