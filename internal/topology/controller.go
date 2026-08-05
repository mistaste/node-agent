package topology

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type Controller struct {
	baseURL, serviceToken, nodeSecret string
	interval                          time.Duration
	http                              *http.Client
	applier                           *Applier
}

type NodeReport struct {
	Role               string `json:"role"`
	WireGuardPublicKey string `json:"wireguard_public_key"`
	ObservedRevision   int64  `json:"observed_revision"`
	Status             string `json:"status"`
	ErrorCode          string `json:"error_code"`
}

func NewController(baseURL, serviceToken, nodeSecret string, interval time.Duration, applier *Applier) (*Controller, error) {
	if applier == nil || !strings.HasPrefix(baseURL, "https://") || strings.TrimSpace(serviceToken) == "" || len(strings.TrimSpace(nodeSecret)) < 32 {
		return nil, errors.New("topology controller configuration is incomplete")
	}
	if interval < 10*time.Second {
		interval = 30 * time.Second
	}
	return &Controller{baseURL: strings.TrimRight(baseURL, "/"), serviceToken: serviceToken, nodeSecret: nodeSecret, interval: interval, http: &http.Client{Timeout: 12 * time.Second}, applier: applier}, nil
}

func (c *Controller) Run(ctx context.Context) {
	c.sync(ctx)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.sync(ctx)
		}
	}
}
func (c *Controller) sync(ctx context.Context) {
	if err := c.SyncOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("[topology] reconciliation deferred: %v", err)
	}
}

func (c *Controller) SyncOnce(ctx context.Context) error {
	state, err := c.fetch(ctx)
	if err != nil {
		return err
	}
	// An unassigned node receives a signed-by-channel empty tombstone. Apply
	// cleanup locally, but do not post an observed role that does not exist.
	if state.Role == "" {
		return c.applier.Apply(ctx, state)
	}
	report := NodeReport{Role: string(state.Role), ObservedRevision: state.Revision, Status: "applied"}
	if state.Role == RoleIngress || state.Role == RoleExit {
		report.WireGuardPublicKey, err = c.applier.PublicKey()
		if err != nil {
			return c.report(ctx, report, "key_generation_failed", err)
		}
	}
	if err = c.applier.Apply(ctx, state); err != nil {
		return c.report(ctx, report, "apply_failed", err)
	}
	if !state.Enabled {
		report.Status = "disabled"
	}
	return c.report(ctx, report, "", nil)
}

func (c *Controller) fetch(ctx context.Context) (DesiredState, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/internal/node/topology", nil)
	if err != nil {
		return DesiredState{}, err
	}
	c.auth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return DesiredState{}, errors.New("topology desired request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return DesiredState{}, fmt.Errorf("topology desired HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return DesiredState{}, errors.New("topology desired response too large")
	}
	var state DesiredState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&state); err != nil {
		return state, errors.New("topology desired response invalid")
	}
	if err = Validate(state); err != nil {
		return state, err
	}
	return state, nil
}
func (c *Controller) report(ctx context.Context, report NodeReport, code string, cause error) error {
	if code != "" {
		report.Status = "degraded"
		report.ErrorCode = code
	}
	body, _ := json.Marshal(map[string]any{"role": report.Role, "wireguard_public_key": report.WireGuardPublicKey, "observed_revision": report.ObservedRevision, "status": report.Status, "error_code": report.ErrorCode})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/internal/node/topology/report", bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.auth(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("topology report failed")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("topology report HTTP %d", resp.StatusCode)
	}
	if cause != nil {
		return cause
	}
	return nil
}
func (c *Controller) auth(req *http.Request) {
	req.Header.Set("X-Service-Token", c.serviceToken)
	req.Header.Set("X-Node-Secret", c.nodeSecret)
	req.Header.Set("Accept", "application/json")
}
