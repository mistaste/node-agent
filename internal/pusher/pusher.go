package pusher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/guardex/node-agent/internal/config"
	"github.com/guardex/node-agent/internal/metrics"
	"github.com/guardex/node-agent/internal/store"
	"github.com/guardex/node-agent/internal/xray"
)

// Pusher periodically sends collected metrics to the Central Controller.
type Pusher struct {
	cfg       *config.Config
	collector *metrics.Collector
	users     userInventory
	http      *http.Client
}

type userInventory interface {
	All() []store.User
}

func NewPusher(cfg *config.Config, collector *metrics.Collector, users userInventory) *Pusher {
	return &Pusher{
		cfg:       cfg,
		collector: collector,
		users:     users,
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
	UserTraffic  []activeUserPayload `json:"user_traffic"`
}

type activeUserPayload struct {
	UUID     string `json:"uuid"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
	LastSeen string `json:"last_seen,omitempty"`
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
	userTraffic := trafficPayload(snap.UserTraffic, provisionedUUIDs(p.users))

	payload := metricsPayload{
		NodeSecret:   p.cfg.Secret,
		AgentVersion: p.cfg.AgentVersion(),
		CPUPercent:   snap.CPUPercent,
		RAMPercent:   snap.MemPercent,
		NetBytesSent: snap.NetBytesSent,
		NetBytesRecv: snap.NetBytesRecv,
		Sessions:     len(activeUsers),
		ActiveUsers:  activeUsers,
		UserTraffic:  userTraffic,
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

// trafficPayload carries monotonic per-user counters independently from the
// short-lived active-session list. A user can finish a small transfer before
// two collector samples observe growth; sending the cumulative counter still
// lets the controller account for those bytes without reporting the user as
// currently online.
func trafficPayload(users []xray.UserTraffic, provisioned map[string]struct{}) []activeUserPayload {
	result := make([]activeUserPayload, 0, len(users))
	for _, user := range users {
		uuid := strings.TrimSpace(user.UUID)
		if uuid == "" || user.Uplink < 0 || user.Downlink < 0 {
			continue
		}
		if _, ok := provisioned[strings.ToLower(uuid)]; !ok {
			continue
		}
		result = append(result, activeUserPayload{
			UUID:     uuid,
			Uplink:   user.Uplink,
			Downlink: user.Downlink,
		})
	}
	return result
}

// provisionedUUIDs takes a fresh snapshot for every push. Xray deliberately
// keeps monotonic stats after RemoveUser, so its stats inventory is not proof
// that an identity is still provisioned. The durable store is the desired user
// inventory for both legacy VLESS and managed Hysteria inbounds.
func provisionedUUIDs(users userInventory) map[string]struct{} {
	result := make(map[string]struct{})
	if users == nil {
		return result
	}
	for _, user := range users.All() {
		uuid := strings.ToLower(strings.TrimSpace(user.UUID))
		if uuid != "" {
			result[uuid] = struct{}{}
		}
	}
	return result
}
