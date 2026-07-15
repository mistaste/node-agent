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
		http: &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Run starts the push loop. Blocks until ctx is cancelled.
//
// The node identifies itself to the controller by its node_secret (AGENT_SECRET),
// so no per-node ID has to be configured — every node that registered auto-pushes.
func (p *Pusher) Run(ctx context.Context) {
	if p.cfg == nil || !p.cfg.ControllerPollingEnabled() {
		log.Println("[pusher] verified HTTPS controller credentials are incomplete — metrics push disabled")
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
	NodeSecret   string              `json:"node_secret"`
	AgentVersion string              `json:"agent_version"`
	CPUPercent   float64             `json:"cpu_percent"`
	RAMPercent   float64             `json:"ram_percent"`
	NetBytesSent uint64              `json:"net_bytes_sent"`
	NetBytesRecv uint64              `json:"net_bytes_recv"`
	Sessions     int                 `json:"sessions"`
	ActiveUsers  []activeUserPayload `json:"active_users"`
}

type activeUserPayload struct {
	UUID     string `json:"uuid"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
	LastSeen string `json:"last_seen"`
}

func (p *Pusher) push(ctx context.Context) error {
	snap := p.collector.Latest()
	if snap == nil {
		return nil
	}

	activeUsers := make([]activeUserPayload, 0, len(snap.ActiveUsers))
	for _, user := range snap.ActiveUsers {
		activeUsers = append(activeUsers, activeUserPayload{
			UUID:     user.UUID,
			Uplink:   user.Uplink,
			Downlink: user.Downlink,
			LastSeen: user.LastSeen.Format(time.RFC3339),
		})
	}

	payload := metricsPayload{
		NodeSecret:   p.cfg.Secret,
		AgentVersion: p.cfg.AgentVersion(),
		CPUPercent:   snap.CPUPercent,
		RAMPercent:   snap.MemPercent,
		NetBytesSent: snap.NetBytesSent,
		NetBytesRecv: snap.NetBytesRecv,
		Sessions:     len(activeUsers),
		ActiveUsers:  activeUsers,
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
