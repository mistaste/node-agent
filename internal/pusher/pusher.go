package pusher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/guardex/node-agent/internal/config"
	"github.com/guardex/node-agent/internal/controlhttp"
	"github.com/guardex/node-agent/internal/metrics"
)

// Pusher periodically sends collected metrics to the Central Controller.
type Pusher struct {
	cfg       *config.Config
	collector *metrics.Collector
	users     UserInventory
	http      *http.Client
}

const (
	metricsRequestTimeout = 5 * time.Second
	metricsPushAttempts   = 2
)

func detectedLinkCapacity(configured, detected int) int {
	if configured > 0 {
		return configured
	}
	if detected > 0 {
		return detected
	}
	return 0
}

type UserInventory interface {
	UUIDs() []string
}

func NewPusher(cfg *config.Config, collector *metrics.Collector, users UserInventory) *Pusher {
	return &Pusher{
		cfg:       cfg,
		collector: collector,
		users:     users,
		http:      newHTTPClient(cfg != nil && cfg.MetricsOnly),
	}
}

func newHTTPClient(_ bool) *http.Client {
	// Ingress/exit agents need the same bounded controller path as relays.
	return controlhttp.NewClient(metricsRequestTimeout, 4*time.Second)
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
	NodeSecret                   string              `json:"node_secret"`
	AgentVersion                 string              `json:"agent_version"`
	CPUPercent                   float64             `json:"cpu_percent"`
	RAMPercent                   float64             `json:"ram_percent"`
	RAMTotalMB                   uint64              `json:"ram_total_mb"`
	CPUCores                     int                 `json:"cpu_cores"`
	NetBytesSent                 uint64              `json:"net_bytes_sent"`
	NetBytesRecv                 uint64              `json:"net_bytes_recv"`
	Sessions                     int                 `json:"sessions"`
	ActiveUsers                  []activeUserPayload `json:"active_users"`
	UserTraffic                  []activeUserPayload `json:"user_traffic"`
	Interface                    string              `json:"interface"`
	LinkCapacityMbps             int                 `json:"link_capacity_mbps"`
	NetPacketsSent               uint64              `json:"net_packets_sent"`
	NetPacketsRecv               uint64              `json:"net_packets_recv"`
	NetErrorsIn                  uint64              `json:"net_errors_in"`
	NetErrorsOut                 uint64              `json:"net_errors_out"`
	NetDropsIn                   uint64              `json:"net_drops_in"`
	NetDropsOut                  uint64              `json:"net_drops_out"`
	TCPConnections               int                 `json:"tcp_connections"`
	UDPConnections               int                 `json:"udp_connections"`
	ConntrackCount               uint64              `json:"conntrack_count"`
	ConntrackMax                 uint64              `json:"conntrack_max"`
	Load1                        float64             `json:"load_1"`
	Load5                        float64             `json:"load_5"`
	Load15                       float64             `json:"load_15"`
	UptimeSeconds                uint64              `json:"uptime_seconds"`
	WireGuardHandshakeAgeSeconds int64               `json:"wireguard_handshake_age_seconds"`
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
		NodeSecret:                   p.cfg.Secret,
		AgentVersion:                 p.cfg.AgentVersion(),
		CPUPercent:                   snap.CPUPercent,
		RAMPercent:                   snap.MemPercent,
		RAMTotalMB:                   snap.MemTotalMB,
		CPUCores:                     runtime.NumCPU(),
		NetBytesSent:                 snap.NetBytesSent,
		NetBytesRecv:                 snap.NetBytesRecv,
		Sessions:                     len(activeUsers),
		ActiveUsers:                  activeUsers,
		UserTraffic:                  userTraffic,
		Interface:                    snap.Interface,
		LinkCapacityMbps:             detectedLinkCapacity(p.cfg.LinkCapacityMbps, snap.LinkCapacityMbps),
		NetPacketsSent:               snap.NetPacketsSent,
		NetPacketsRecv:               snap.NetPacketsRecv,
		NetErrorsIn:                  snap.NetErrorsIn,
		NetErrorsOut:                 snap.NetErrorsOut,
		NetDropsIn:                   snap.NetDropsIn,
		NetDropsOut:                  snap.NetDropsOut,
		TCPConnections:               snap.TCPConnections,
		UDPConnections:               snap.UDPConnections,
		ConntrackCount:               snap.ConntrackCount,
		ConntrackMax:                 snap.ConntrackMax,
		Load1:                        snap.Load1,
		Load5:                        snap.Load5,
		Load15:                       snap.Load15,
		UptimeSeconds:                snap.UptimeSeconds,
		WireGuardHandshakeAgeSeconds: snap.WireGuardHandshakeAgeSeconds,
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

	return p.send(req, body)
}

func (p *Pusher) send(req *http.Request, body []byte) error {
	attempts := metricsPushAttempts

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		request := req
		if attempt > 0 {
			if err := req.Context().Err(); err != nil {
				return fmt.Errorf("http: %w", err)
			}
			request = req.Clone(req.Context())
			request.Body = io.NopCloser(bytes.NewReader(body))
			request.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(body)), nil
			}
		}
		resp, err := p.http.Do(request)
		if err != nil {
			lastErr = err
			p.http.CloseIdleConnections()
			continue
		}
		// Successful metrics responses contain a small JSON body. Reading it is
		// necessary to reuse H1 connections; Close alone discards the connection.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode >= http.StatusMultipleChoices {
			return fmt.Errorf("controller returned %d", resp.StatusCode)
		}
		return nil
	}
	return fmt.Errorf("http: %w", lastErr)
}

// trafficPayload carries monotonic per-user counters independently from the
// short-lived active-session list. A user can finish a small transfer before
// two collector samples observe growth; sending the cumulative counter still
// lets the controller account for those bytes without reporting the user as
// currently online.
func trafficPayload(users []metrics.UserTraffic, provisioned map[string]struct{}) []activeUserPayload {
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

// provisionedUUIDs snapshots successfully applied native membership for each push.
func provisionedUUIDs(users UserInventory) map[string]struct{} {
	result := make(map[string]struct{})
	if users == nil {
		return result
	}
	for _, value := range users.UUIDs() {
		uuid := strings.ToLower(strings.TrimSpace(value))
		if uuid != "" {
			result[uuid] = struct{}{}
		}
	}
	return result
}
