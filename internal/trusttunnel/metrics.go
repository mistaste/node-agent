package trusttunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ClientMetric is the endpoint's authenticated, server-side traffic view.
// Username is the Guardex profile UUID; IP is deliberately not retained.
type ClientMetric struct {
	Username string `json:"username"`
	Sessions int    `json:"sessions"`
	Inbound  int64  `json:"inbound"`
	Outbound int64  `json:"outbound"`
}

type MetricsClient struct {
	endpoint string
	http     *http.Client
}

func NewMetricsClient(endpoint string) *MetricsClient {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	transport := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 2 * time.Second,
		DialContext: (&net.Dialer{
			Timeout: 2 * time.Second,
		}).DialContext,
	}
	return &MetricsClient{
		endpoint: endpoint,
		http:     &http.Client{Transport: transport, Timeout: 3 * time.Second},
	}
}

func (c *MetricsClient) Clients(ctx context.Context) ([]ClientMetric, error) {
	if c == nil || c.endpoint == "" {
		return nil, nil
	}
	parsed, err := url.Parse(c.endpoint + "/clients")
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" {
		return nil, fmt.Errorf("trusttunnel metrics endpoint must be loopback HTTP")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trusttunnel clients returned %d", resp.StatusCode)
	}
	var clients []ClientMetric
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		return nil, fmt.Errorf("decode trusttunnel clients: %w", err)
	}
	result := clients[:0]
	for _, client := range clients {
		client.Username = strings.ToLower(strings.TrimSpace(client.Username))
		if client.Username == "" || client.Sessions < 0 || client.Inbound < 0 || client.Outbound < 0 {
			continue
		}
		result = append(result, client)
	}
	return result, nil
}
