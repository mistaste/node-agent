// Package controller implements the outbound-only desired/observed control
// plane. Nodes poll the backend over verified HTTPS, reconcile a fully
// validated manifest, then report terminal state without exposing private
// endpoint credentials.
package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/guardex/node-agent/internal/config"
	"github.com/guardex/node-agent/internal/inbound"
	"github.com/guardex/node-agent/internal/transportbundle"
	"github.com/guardex/node-agent/internal/trusttunnel"
	"github.com/guardex/node-agent/internal/userops"
)

const (
	maxManifestBytes = 8 << 20
	maxReportBytes   = 1 << 20
	maxManifestItems = 512
	requestTimeout   = 12 * time.Second
)

func rejectRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type desiredResponse struct {
	ServerID    string        `json:"server_id"`
	GeneratedAt time.Time     `json:"generated_at"`
	Items       []desiredItem `json:"items"`
}

type desiredItem struct {
	InboundID       string          `json:"inbound_id"`
	Engine          string          `json:"engine,omitempty"`
	Code            string          `json:"code,omitempty"`
	Action          string          `json:"action"`
	DesiredRevision int64           `json:"desired_revision"`
	EffectiveTag    string          `json:"effective_tag"`
	EffectivePort   int             `json:"effective_port"`
	UserFlow        string          `json:"user_flow"`
	ConfigJSON      json.RawMessage `json:"config_json"`
	ClientUUIDs     []string        `json:"client_uuids"`
	ClientCount     *int            `json:"client_count,omitempty"`
	ClientSetSHA256 string          `json:"client_set_sha256,omitempty"`
}

type preparedItem struct {
	desired desiredItem

	desiredDigest  string
	publicMaterial json.RawMessage
	clientParams   json.RawMessage
	clientSecret   json.RawMessage

	clientCount     int
	clientSetSHA256 string
	trustTunnel     *trusttunnel.Endpoint
	transportBundle *transportbundle.Config
}

type deploymentReport struct {
	InboundID              string          `json:"inbound_id"`
	AppliedRevision        int64           `json:"applied_revision"`
	EffectiveTag           string          `json:"effective_tag"`
	EffectivePort          int             `json:"effective_port"`
	Status                 string          `json:"status"`
	PublicMaterialJSON     json.RawMessage `json:"public_material_json"`
	ClientParamsJSON       json.RawMessage `json:"client_params_json"`
	ClientSecretJSON       json.RawMessage `json:"client_secret_json"`
	AppliedClientCount     int             `json:"applied_client_count"`
	AppliedClientSetSHA256 string          `json:"applied_client_set_sha256"`
	ErrorCode              string          `json:"error_code"`
	ErrorMessage           string          `json:"error_message"`
}

type capabilitiesReport struct {
	AgentVersion        string          `json:"agent_version"`
	CoreVersion         string          `json:"core_version"`
	SupportedProtocols  []string        `json:"supported_protocols"`
	SupportedTransports []string        `json:"supported_transports"`
	SupportedSecurities []string        `json:"supported_securities"`
	SupportedEngines    []string        `json:"supported_engines"`
	RawJSON             json.RawMessage `json:"raw_json"`
}

type observedReport struct {
	Capabilities capabilitiesReport `json:"capabilities"`
	Deployments  []deploymentReport `json:"deployments"`
}

// Reconciler serializes native runtime mutations and tracks applied membership.
type Reconciler struct {
	inventoryMu sync.RWMutex
	inventory   map[string][]string
	cfg         *config.Config

	http                    *http.Client
	baseURL                 string
	interval                time.Duration
	userOps                 *userops.Coordinator
	trustTunnel             trustTunnelRuntime
	trustTunnelApplyEnabled bool
	transportBundle         transportBundleRuntime
	naivePin                func(context.Context, string, int) (string, error)
}

type trustTunnelRuntime interface {
	Available(context.Context) bool
	Apply(context.Context, trusttunnel.ApplyRequest) (trusttunnel.State, error)
	Remove(context.Context, string, int64) error
	State() (trusttunnel.State, bool)
}

type transportBundleRuntime interface {
	Apply(context.Context, transportbundle.ApplyRequest) (transportbundle.State, error)
	Remove(context.Context, string, int64) error
	State() (transportbundle.State, bool)
}

// EnableTrustTunnel adds the independently managed endpoint runtime.
func (r *Reconciler) EnableTrustTunnel(runtime trustTunnelRuntime) {
	r.trustTunnel = runtime
	r.trustTunnelApplyEnabled = true
}

// EnableTrustTunnelCleanup keeps tombstone processing available on nodes
// where new TrustTunnel endpoints are disabled. This prevents a previously
// active endpoint from surviving a feature-flag rollback.
func (r *Reconciler) EnableTrustTunnelCleanup(runtime trustTunnelRuntime) {
	r.trustTunnel = runtime
	r.trustTunnelApplyEnabled = false
}

func (r *Reconciler) EnableTransportBundle(runtime transportBundleRuntime) {
	r.transportBundle = runtime
}

// IsNaiveTag reports whether tag belongs to the active NaiveProxy bundle.
// It lets the authenticated direct-user API route membership refreshes to the
// controller reconciler.
func (r *Reconciler) IsNaiveTag(tag string) bool {
	if r.transportBundle == nil {
		return false
	}
	state, ok := r.transportBundle.State()
	return ok && strings.TrimSpace(state.Tag) == strings.TrimSpace(tag)
}

func New(cfg *config.Config) (*Reconciler, error) {
	if cfg == nil || !cfg.ControllerPollingEnabled() {
		return nil, errors.New("controller requires verified HTTPS credentials")
	}
	parsed, err := url.Parse(strings.TrimSpace(cfg.ControllerURL))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("invalid controller origin")
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return &Reconciler{cfg: cfg, http: &http.Client{Timeout: requestTimeout, CheckRedirect: rejectRedirect}, baseURL: strings.TrimRight(parsed.String(), "/"), interval: normalizedInterval(cfg.ResyncInterval), userOps: userops.New()}, nil
}

func normalizedInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return 30 * time.Second
	}
	return interval
}

// Run performs one startup reconciliation immediately, then retries forever at
// the bounded resync interval. Fetch/auth/JSON failures never mutate inventory.
func (r *Reconciler) Run(ctx context.Context) {
	r.syncAndLog(ctx)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.syncAndLog(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (r *Reconciler) syncAndLog(ctx context.Context) {
	if err := r.SyncOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
		// Errors are intentionally classified and contain no tokens, configs,
		// UUIDs, private keys, response bodies, or controller query strings.
		log.Printf("[controller-inbounds] reconciliation deferred: %v", err)
	}
}

// SyncOnce fetches and fully validates the whole manifest before the first
// mutation, then applies each item and reports terminal observed state.
func (r *Reconciler) SyncOnce(ctx context.Context) error {
	// This lock intentionally starts before the pull. Backend user mutations use
	// the direct node API after their DB commit: they either finish before this
	// fetch (and therefore appear in the manifest), or wait and execute after the
	// old manifest has reconciled. Holding it for a bounded GET is what closes the
	// stale-fetch window; reporting does not mutate runtime and happens unlocked.
	if err := r.userOps.LockContext(ctx); err != nil {
		return err
	}
	items, err := r.fetchDesired(ctx)
	if err != nil {
		r.userOps.Unlock()
		return err
	}
	prepared, validationReports, err := r.prepareManifest(items)
	if err != nil {
		r.userOps.Unlock()
		if len(validationReports) > 0 {
			if reportErr := r.report(ctx, validationReports); reportErr != nil {
				return reportErr
			}
		}
		return err
	}
	if err := ctx.Err(); err != nil {
		r.userOps.Unlock()
		return err
	}
	// A bundle apply requires TrustTunnel to move behind the mux first. A bundle
	// delete must release public 443 before TrustTunnel moves back onto it.
	sort.SliceStable(prepared, func(i, j int) bool {
		left, right := prepared[i].desired, prepared[j].desired
		if left.Engine == "naiveproxy" && left.Action == "delete" {
			return true
		}
		if right.Engine == "naiveproxy" && right.Action == "delete" {
			return false
		}
		if left.Engine == "naiveproxy" && left.Action == "apply" {
			return false
		}
		if right.Engine == "naiveproxy" && right.Action == "apply" {
			return true
		}
		return false
	})
	// An internal TrustTunnel listener is valid only while an active Naive mux
	// owns the public socket. A Naive tombstone must therefore move TrustTunnel
	// back to its advertised port in the same reconciliation cycle.
	hasNaiveApply := false
	for _, item := range prepared {
		if item.desired.Engine == "naiveproxy" && item.desired.Action == "apply" {
			hasNaiveApply = true
			break
		}
	}
	if !hasNaiveApply {
		for index := range prepared {
			item := &prepared[index]
			if item.desired.Engine == "trusttunnel" && item.desired.Action == "apply" && item.trustTunnel != nil {
				item.trustTunnel.Port = item.desired.EffectivePort
			}
		}
	}

	reports := make([]deploymentReport, 0, len(prepared))
	failed := 0
	for _, item := range prepared {
		if err := ctx.Err(); err != nil {
			r.userOps.Unlock()
			return err
		}
		report := r.reconcileOne(ctx, item)
		r.inventoryMu.Lock()
		if r.inventory == nil {
			r.inventory = make(map[string][]string)
		}
		if report.Status == "active" {
			r.inventory[item.desired.InboundID] = append([]string(nil), item.desired.ClientUUIDs...)
		} else if report.Status == "deleted" {
			delete(r.inventory, item.desired.InboundID)
		}
		r.inventoryMu.Unlock()
		if report.Status != "active" && report.Status != "deleted" {
			failed++
			if item.desired.Engine == "naiveproxy" && item.desired.Action == "apply" {
				r.restoreTrustTunnelPublicListener(ctx, prepared)
			}
		}
		reports = append(reports, report)
	}
	r.userOps.Unlock()
	if err := r.report(ctx, reports); err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("%d desired inbound operations failed", failed)
	}
	return nil
}

func (r *Reconciler) restoreTrustTunnelPublicListener(ctx context.Context, prepared []preparedItem) {
	if r.trustTunnel == nil {
		return
	}
	for _, item := range prepared {
		if item.desired.Engine != "trusttunnel" || item.desired.Action != "apply" || item.trustTunnel == nil || item.trustTunnel.Port == item.desired.EffectivePort {
			continue
		}
		fallback := *item.trustTunnel
		fallback.Port = item.desired.EffectivePort
		_, _ = r.trustTunnel.Apply(ctx, trusttunnel.ApplyRequest{InboundID: item.desired.InboundID, Tag: item.desired.EffectiveTag, Revision: item.desired.DesiredRevision, Endpoint: fallback, ClientSetSHA256: item.clientSetSHA256})
		return
	}
}

func (r *Reconciler) fetchDesired(ctx context.Context) ([]desiredItem, error) {
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, r.baseURL+"/v1/internal/node/inbounds", nil)
	if err != nil {
		return nil, errors.New("build desired-state request failed")
	}
	r.setAuthHeaders(req)
	req.Header.Set("Accept", "application/json")
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, errors.New("controller desired-state request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		drainResponse(resp.Body)
		return nil, fmt.Errorf("controller desired-state returned HTTP %d", resp.StatusCode)
	}
	body, err := readBounded(resp.Body, maxManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("controller desired-state response rejected: %w", err)
	}
	var response desiredResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return nil, errors.New("controller desired-state response is invalid JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("controller desired-state response contains trailing data")
	}
	response.ServerID = strings.TrimSpace(response.ServerID)
	if response.ServerID == "" {
		return nil, errors.New("controller desired-state response omitted server identity")
	}
	if expected := strings.TrimSpace(r.cfg.NodeID); expected != "" && response.ServerID != expected {
		return nil, errors.New("controller desired-state response belongs to another node")
	}
	if len(response.Items) > maxManifestItems {
		return nil, fmt.Errorf("controller desired-state exceeds %d items", maxManifestItems)
	}
	return response.Items, nil
}

func (r *Reconciler) prepareManifest(items []desiredItem) ([]preparedItem, []deploymentReport, error) {
	prepared := make([]preparedItem, len(items))
	errorsByIndex := make(map[int]itemError)
	inboundIDs := make(map[string]int, len(items))
	tags := make(map[string]int, len(items))
	listeners := make(map[string]int, len(items))
	trustTunnelItems := make([]int, 0, 1)

	for index, item := range items {
		item.InboundID = strings.TrimSpace(item.InboundID)
		item.Action = strings.ToLower(strings.TrimSpace(item.Action))
		item.Engine = strings.ToLower(strings.TrimSpace(item.Engine))
		if item.Engine == "" {
			item.Engine = "unsupported"
		}
		item.EffectiveTag = strings.TrimSpace(item.EffectiveTag)
		item.UserFlow = strings.TrimSpace(item.UserFlow)
		prepared[index].desired = item

		if item.InboundID == "" || len(item.InboundID) > 128 {
			errorsByIndex[index] = itemError{"invalid_identity", "desired inbound identity is invalid"}
			continue
		}
		if previous, duplicate := inboundIDs[item.InboundID]; duplicate {
			errorsByIndex[index] = itemError{"duplicate_identity", "manifest contains a duplicate inbound identity"}
			errorsByIndex[previous] = itemError{"duplicate_identity", "manifest contains a duplicate inbound identity"}
		} else {
			inboundIDs[item.InboundID] = index
		}
		if item.Action != "apply" && item.Action != "delete" {
			errorsByIndex[index] = itemError{"unsupported_action", "desired inbound action is unsupported"}
			continue
		}
		if item.Engine != "trusttunnel" && item.Engine != "naiveproxy" {
			errorsByIndex[index] = itemError{"unsupported_engine", "desired tunnel engine is unsupported"}
			continue
		}
		if item.Engine == "trusttunnel" && item.Action == "apply" && (!r.trustTunnelApplyEnabled || r.trustTunnel == nil) {
			errorsByIndex[index] = itemError{"engine_unavailable", "TrustTunnel runtime is not enabled on this node"}
			continue
		}
		if item.Engine == "naiveproxy" && item.Action == "apply" && r.transportBundle == nil {
			errorsByIndex[index] = itemError{"engine_unavailable", "NaiveProxy transport bundle runtime is not enabled on this node"}
			continue
		}
		if item.Engine == "trusttunnel" && item.Action == "apply" {
			trustTunnelItems = append(trustTunnelItems, index)
		}
		if item.DesiredRevision < 1 {
			errorsByIndex[index] = itemError{"invalid_revision", "desired inbound revision is invalid"}
			continue
		}
		if err := inbound.ValidateIdentity(item.EffectiveTag, item.EffectivePort); err != nil {
			errorsByIndex[index] = itemError{"invalid_listener", "desired inbound listener identity is invalid"}
			continue
		}
		if !inbound.IsControllerManagedTag(item.EffectiveTag) {
			errorsByIndex[index] = itemError{"protected_inbound", "desired inbound tag is outside the controller namespace"}
			continue
		}
		if previous, duplicate := tags[item.EffectiveTag]; duplicate {
			errorsByIndex[index] = itemError{"duplicate_tag", "manifest contains a duplicate effective tag"}
			errorsByIndex[previous] = itemError{"duplicate_tag", "manifest contains a duplicate effective tag"}
		} else {
			tags[item.EffectiveTag] = index
		}
	}
	if len(trustTunnelItems) > 1 {
		for _, index := range trustTunnelItems {
			errorsByIndex[index] = itemError{"engine_instance_conflict", "node supports one TrustTunnel endpoint instance"}
		}
	}

	for index := range prepared {
		if _, invalid := errorsByIndex[index]; invalid {
			continue
		}
		if prepared[index].desired.Action == "delete" {
			continue
		}
		item, err := r.prepareApply(prepared[index].desired)
		if err != nil {
			errorsByIndex[index] = itemError{"invalid_desired_config", "desired inbound config failed validation"}
			continue
		}
		prepared[index] = item
		listenerNetwork := "tcp"
		if item.trustTunnel != nil && item.trustTunnel.EnableHTTP3 && !item.trustTunnel.EnableHTTP1 && !item.trustTunnel.EnableHTTP2 {
			listenerNetwork = "udp"
		}
		if item.desired.EffectivePort == 443 && (item.desired.Engine == "trusttunnel" || item.desired.Engine == "naiveproxy") {
			listenerNetwork = "mux-" + item.desired.Engine
		}
		if item.trustTunnel == nil && listenerNetwork == "tcp" && item.desired.EffectivePort == 443 {
			errorsByIndex[index] = itemError{"protected_port", "TCP port 443 belongs to the static baseline inbound"}
			continue
		}
		listenerKey := fmt.Sprintf("%s:%d", listenerNetwork, item.desired.EffectivePort)
		if previous, duplicate := listeners[listenerKey]; duplicate {
			errorsByIndex[index] = itemError{"duplicate_port", "manifest contains a duplicate effective listener"}
			errorsByIndex[previous] = itemError{"duplicate_port", "manifest contains a duplicate effective listener"}
		} else {
			listeners[listenerKey] = index
		}
	}

	if len(errorsByIndex) == 0 {
		return prepared, nil, nil
	}
	reports := make([]deploymentReport, 0, len(items))
	validationCodes := make(map[string]struct{}, len(errorsByIndex))
	for index, item := range prepared {
		itemErr, invalid := errorsByIndex[index]
		forceDegraded := invalid
		if !invalid {
			itemErr = itemError{"manifest_rejected", "manifest was not applied because another item is invalid"}
		} else {
			validationCodes[itemErr.code] = struct{}{}
		}
		if item.desired.InboundID == "" {
			continue
		}
		reports = append(reports, r.failedReportPreservingLKG(item.desired, itemErr, forceDegraded))
	}
	codes := make([]string, 0, len(validationCodes))
	for code := range validationCodes {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	return nil, reports, fmt.Errorf("controller manifest failed whole-manifest validation (%s)", strings.Join(codes, ","))
}

func (r *Reconciler) prepareApply(item desiredItem) (preparedItem, error) {
	if item.UserFlow != "" {
		return preparedItem{}, errors.New("native transports do not use flow overrides")
	}
	clients, clientHash, err := normalizeClientUUIDs(item.ClientUUIDs)
	if err != nil {
		return preparedItem{}, err
	}
	if item.ClientCount != nil && *item.ClientCount != len(clients) {
		return preparedItem{}, errors.New("client count does not match UUID set")
	}
	if item.ClientSetSHA256 != "" && !strings.EqualFold(strings.TrimSpace(item.ClientSetSHA256), clientHash) {
		return preparedItem{}, errors.New("client digest does not match UUID set")
	}
	if len(item.ConfigJSON) == 0 || len(item.ConfigJSON) > inbound.MaxConfigBytes {
		return preparedItem{}, errors.New("desired config is empty or too large")
	}
	if item.Engine == "trusttunnel" {
		return r.prepareTrustTunnelApply(item, clients, clientHash)
	}
	if item.Engine == "naiveproxy" {
		return r.prepareNaiveProxyApply(item, clients, clientHash)
	}

	return preparedItem{}, errors.New("unsupported engine")
}

func (r *Reconciler) prepareNaiveProxyApply(item desiredItem, clients []string, clientHash string) (preparedItem, error) {
	var config struct {
		Protocol            string `json:"protocol"`
		Hostname            string `json:"hostname"`
		TrustTunnelHostname string `json:"trusttunnel_hostname"`
		TrustTunnelPort     int    `json:"trusttunnel_port"`
		NaivePort           int    `json:"naive_port"`
		DecoyPort           int    `json:"decoy_port"`
		CertificateFile     string `json:"certificate_file"`
		PrivateKeyFile      string `json:"private_key_file"`
		Tag                 string `json:"tag"`
		Port                int    `json:"port"`
		Transport           string `json:"transport"`
		Security            string `json:"security"`
	}
	decoder := json.NewDecoder(bytes.NewReader(item.ConfigJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil || strings.ToLower(strings.TrimSpace(config.Protocol)) != "naive" {
		return preparedItem{}, errors.New("NaiveProxy config is invalid")
	}
	root := strings.TrimSpace(r.cfg.TrustTunnelRoot)
	if root == "" {
		root = "/etc/guardex/trusttunnel"
	}
	if config.CertificateFile == "" {
		config.CertificateFile = filepath.Join(root, "certs", "fullchain.pem")
	}
	if config.PrivateKeyFile == "" {
		config.PrivateKeyFile = filepath.Join(root, "certs", "privkey.pem")
	}
	bundle := transportbundle.Config{PublicPort: item.EffectivePort, TrustTunnelHostname: config.TrustTunnelHostname, TrustTunnelPort: config.TrustTunnelPort, NaiveHostname: config.Hostname, NaivePort: config.NaivePort, DecoyPort: config.DecoyPort, CertificateFile: config.CertificateFile, PrivateKeyFile: config.PrivateKeyFile, ClientUUIDs: clients}
	if _, err := transportbundle.Build(r.cfg.Secret, bundle); err != nil {
		return preparedItem{}, err
	}
	digestRaw, _ := json.Marshal(struct {
		Config  json.RawMessage `json:"config"`
		Clients []string        `json:"clients"`
	}{Config: item.ConfigJSON, Clients: clients})
	digest := sha256.Sum256(digestRaw)
	clientParams := json.RawMessage(`{}`)
	// This file belongs to the decoy, not Caddy's managed Naive certificate.
	if _, err := certificateSPKIPin(config.CertificateFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return preparedItem{}, fmt.Errorf("NaiveProxy certificate is invalid: %w", err)
	}
	return preparedItem{desired: item, desiredDigest: hex.EncodeToString(digest[:]), publicMaterial: json.RawMessage(`{}`), clientParams: clientParams, clientSecret: json.RawMessage(`{}`), clientCount: len(clients), clientSetSHA256: clientHash, transportBundle: &bundle}, nil
}

// prepareTrustTunnelApply validates the native endpoint and client membership.
func (r *Reconciler) prepareTrustTunnelApply(item desiredItem, clients []string, clientHash string) (preparedItem, error) {
	var config struct {
		Protocol                 string   `json:"protocol"`
		Hostname                 string   `json:"hostname"`
		DNSUpstreams             []string `json:"dns_upstreams"`
		HasIPv6                  *bool    `json:"has_ipv6"`
		UpstreamFallbackProtocol string   `json:"upstream_fallback_protocol"`
		UpstreamProtocol         string   `json:"upstream_protocol"`
		CertificateFile          string   `json:"certificate_file"`
		ListenPort               int      `json:"listen_port"`
	}
	decoder := json.NewDecoder(bytes.NewReader(item.ConfigJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		// Desired state also contains the generic identity fields. Decode through
		// an allowlisted map below while rejecting every unknown operational key.
		var root map[string]any
		if json.Unmarshal(item.ConfigJSON, &root) != nil {
			return preparedItem{}, errors.New("TrustTunnel config is invalid")
		}
		allowed := map[string]bool{"protocol": true, "hostname": true, "dns_upstreams": true, "has_ipv6": true, "upstream_protocol": true, "upstream_fallback_protocol": true, "certificate_file": true, "tls_hosts_file": true, "anti_dpi": true, "listen_port": true, "tag": true, "port": true}
		for key := range root {
			if !allowed[strings.ToLower(strings.TrimSpace(key))] {
				return preparedItem{}, errors.New("TrustTunnel config contains an unsupported field")
			}
		}
		raw, _ := json.Marshal(root)
		if json.Unmarshal(raw, &config) != nil {
			return preparedItem{}, errors.New("TrustTunnel config is invalid")
		}
	}
	if strings.ToLower(strings.TrimSpace(config.Protocol)) != "trusttunnel" {
		return preparedItem{}, errors.New("TrustTunnel config protocol is invalid")
	}
	hostname := strings.ToLower(strings.TrimSpace(config.Hostname))
	if hostname == "" {
		return preparedItem{}, errors.New("TrustTunnel config omitted TLS hostname")
	}
	root := strings.TrimSpace(r.cfg.TrustTunnelRoot)
	cert := strings.TrimSpace(config.CertificateFile)
	if cert == "" {
		cert = filepath.Join(root, "certs", "fullchain.pem")
	}
	// IPv6 is opt-in. Claiming it on an IPv4-only node produces a tunnel that
	// appears connected while silently black-holing IPv6 destinations.
	ipv6 := false
	if config.HasIPv6 != nil {
		ipv6 = *config.HasIPv6
	}
	upstream := strings.ToLower(strings.TrimSpace(config.UpstreamProtocol))
	if upstream != "http2" && upstream != "http3" {
		return preparedItem{}, errors.New("TrustTunnel upstream protocol is invalid")
	}
	fallback := strings.ToLower(strings.TrimSpace(config.UpstreamFallbackProtocol))
	http2 := upstream == "http2" || fallback == "http2"
	http3 := upstream == "http3" || fallback == "http3"
	listenPort := item.EffectivePort
	if config.ListenPort != 0 {
		if config.ListenPort < 1024 || config.ListenPort > 65535 || config.ListenPort == 443 {
			return preparedItem{}, errors.New("TrustTunnel internal listen port is invalid")
		}
		listenPort = config.ListenPort
	}
	endpoint := trusttunnel.Endpoint{Port: listenPort, Hostname: hostname, CertificateFile: cert, PrivateKeyFile: filepath.Join(root, "certs", "privkey.pem"), ClientUUIDs: clients, EnableHTTP1: false, EnableHTTP2: http2, EnableHTTP3: http3, IPv6Available: ipv6}
	digestRaw, _ := json.Marshal(struct {
		Config  json.RawMessage `json:"config"`
		Clients []string        `json:"clients"`
	}{Config: item.ConfigJSON, Clients: clients})
	digest := sha256.Sum256(digestRaw)
	clientParams := json.RawMessage(`{}`)
	if pin, err := certificateSPKIPin(cert); err == nil {
		clientParams, _ = json.Marshal(map[string]any{"spki_pins_sha256": []string{pin}})
	} else if !errors.Is(err, os.ErrNotExist) {
		return preparedItem{}, fmt.Errorf("TrustTunnel certificate is invalid: %w", err)
	}
	return preparedItem{desired: item, desiredDigest: hex.EncodeToString(digest[:]), publicMaterial: json.RawMessage(`{}`), clientParams: clientParams, clientSecret: json.RawMessage(`{}`), clientCount: len(clients), clientSetSHA256: clientHash, trustTunnel: &endpoint}, nil
}

func certificateSPKIPin(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("certificate PEM is missing")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	spki, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(spki)
	return base64.StdEncoding.EncodeToString(digest[:]), nil
}

func (r *Reconciler) reconcileOne(ctx context.Context, item preparedItem) deploymentReport {
	if item.desired.Engine == "trusttunnel" {
		return r.reconcileTrustTunnel(ctx, item)
	}
	if item.desired.Engine == "naiveproxy" {
		return r.reconcileNaiveProxy(ctx, item)
	}
	return failedReport(item.desired, 0, itemError{"unsupported_engine", "unsupported tunnel engine"})
}

func (r *Reconciler) reconcileNaiveProxy(ctx context.Context, item preparedItem) deploymentReport {
	desired := item.desired
	if r.transportBundle == nil {
		return failedReport(desired, 0, itemError{"engine_unavailable", "NaiveProxy transport bundle runtime is not enabled"})
	}
	if desired.Action == "delete" {
		if err := r.transportBundle.Remove(ctx, desired.InboundID, desired.DesiredRevision); err != nil {
			return failedReport(desired, 0, itemError{"delete_failed", "node could not remove the NaiveProxy transport bundle"})
		}
		return deploymentReport{InboundID: desired.InboundID, AppliedRevision: desired.DesiredRevision, EffectiveTag: desired.EffectiveTag, EffectivePort: desired.EffectivePort, Status: "deleted", PublicMaterialJSON: json.RawMessage(`{}`), ClientParamsJSON: json.RawMessage(`{}`), ClientSecretJSON: json.RawMessage(`{}`), AppliedClientSetSHA256: emptyClientSetHash()}
	}
	if item.transportBundle == nil {
		return failedReport(desired, 0, itemError{"invalid_desired_config", "NaiveProxy transport bundle settings are unavailable"})
	}
	state, err := r.transportBundle.Apply(ctx, transportbundle.ApplyRequest{InboundID: desired.InboundID, Tag: desired.EffectiveTag, Revision: desired.DesiredRevision, Config: *item.transportBundle, ClientSetSHA256: item.clientSetSHA256})
	if err != nil {
		previous := int64(0)
		if current, ok := r.transportBundle.State(); ok && current.InboundID == desired.InboundID {
			previous = current.Revision
		}
		return failedReport(desired, previous, itemError{"apply_failed", "node could not activate the NaiveProxy transport bundle"})
	}
	probe := r.naivePin
	if probe == nil {
		probe = naiveListenerPin
	}
	pin, err := probe(ctx, item.transportBundle.NaiveHostname, item.transportBundle.NaivePort)
	if err != nil {
		return failedReport(desired, state.Revision, itemError{"certificate_probe_failed", "node could not verify the active Naive TLS certificate"})
	}
	params, _ := json.Marshal(map[string]any{"spki_pins_sha256": []string{pin}})
	return deploymentReport{InboundID: desired.InboundID, AppliedRevision: state.Revision, EffectiveTag: desired.EffectiveTag, EffectivePort: desired.EffectivePort, Status: "active", PublicMaterialJSON: json.RawMessage(`{}`), ClientParamsJSON: params, ClientSecretJSON: json.RawMessage(`{}`), AppliedClientCount: state.ClientCount, AppliedClientSetSHA256: state.ClientSetSHA256}
}

func (r *Reconciler) reconcileTrustTunnel(ctx context.Context, item preparedItem) deploymentReport {
	desired := item.desired
	if r.trustTunnel == nil {
		return failedReport(desired, 0, itemError{"engine_unavailable", "TrustTunnel runtime is not enabled"})
	}
	if desired.Action == "delete" {
		if err := r.trustTunnel.Remove(ctx, desired.InboundID, desired.DesiredRevision); err != nil {
			return failedReport(desired, 0, itemError{"delete_failed", "node could not remove the TrustTunnel endpoint"})
		}
		return deploymentReport{InboundID: desired.InboundID, AppliedRevision: desired.DesiredRevision, EffectiveTag: desired.EffectiveTag, EffectivePort: desired.EffectivePort, Status: "deleted", PublicMaterialJSON: json.RawMessage(`{}`), ClientParamsJSON: json.RawMessage(`{}`), ClientSecretJSON: json.RawMessage(`{}`), AppliedClientSetSHA256: emptyClientSetHash()}
	}
	if item.trustTunnel == nil {
		return failedReport(desired, 0, itemError{"invalid_desired_config", "TrustTunnel endpoint settings are unavailable"})
	}
	state, err := r.trustTunnel.Apply(ctx, trusttunnel.ApplyRequest{InboundID: desired.InboundID, Tag: desired.EffectiveTag, Revision: desired.DesiredRevision, Endpoint: *item.trustTunnel, ClientSetSHA256: item.clientSetSHA256})
	if err != nil {
		previous := int64(0)
		if current, ok := r.trustTunnel.State(); ok && current.InboundID == desired.InboundID {
			previous = current.Revision
		}
		return failedReport(desired, previous, itemError{"apply_failed", "node could not activate the TrustTunnel endpoint"})
	}
	return deploymentReport{InboundID: desired.InboundID, AppliedRevision: state.Revision, EffectiveTag: desired.EffectiveTag, EffectivePort: desired.EffectivePort, Status: "active", PublicMaterialJSON: json.RawMessage(`{}`), ClientParamsJSON: item.clientParams, ClientSecretJSON: json.RawMessage(`{}`), AppliedClientCount: state.ClientCount, AppliedClientSetSHA256: state.ClientSetSHA256}
}

func (r *Reconciler) failedReportPreservingLKG(item desiredItem, problem itemError, forceDegraded bool) deploymentReport {
	report := failedReport(item, 0, problem)
	if item.Engine == "trusttunnel" && r.trustTunnel != nil {
		if st, ok := r.trustTunnel.State(); ok && st.InboundID == item.InboundID {
			report.AppliedRevision = st.Revision
			report.AppliedClientCount = st.ClientCount
			report.AppliedClientSetSHA256 = st.ClientSetSHA256
		}
	}
	if item.Engine == "naiveproxy" && r.transportBundle != nil {
		if st, ok := r.transportBundle.State(); ok && st.InboundID == item.InboundID {
			report.AppliedRevision = st.Revision
			report.AppliedClientCount = st.ClientCount
			report.AppliedClientSetSHA256 = st.ClientSetSHA256
		}
	}
	if report.AppliedRevision > 0 {
		report.Status = "degraded"
	}
	return report
}

func jsonObjectOrEmpty(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || !json.Valid(raw) {
		return json.RawMessage(`{}`)
	}
	return append(json.RawMessage(nil), raw...)
}

func normalizedReportPort(port int) int {
	if port < 1 || port > 65535 {
		return 1
	}
	return port
}

type itemError struct {
	code    string
	message string
}

func failedReport(item desiredItem, appliedRevision int64, problem itemError) deploymentReport {
	port := normalizedReportPort(item.EffectivePort)
	if appliedRevision < 0 {
		appliedRevision = 0
	}
	return deploymentReport{
		InboundID:              sanitizeText(item.InboundID, 128),
		AppliedRevision:        appliedRevision,
		EffectiveTag:           sanitizedTag(item.EffectiveTag),
		EffectivePort:          port,
		Status:                 "failed",
		PublicMaterialJSON:     json.RawMessage(`{}`),
		ClientParamsJSON:       json.RawMessage(`{}`),
		ClientSecretJSON:       json.RawMessage(`{}`),
		AppliedClientSetSHA256: emptyClientSetHash(),
		ErrorCode:              sanitizeText(problem.code, 128),
		ErrorMessage:           sanitizeText(problem.message, 512),
	}
}

func sanitizedTag(tag string) string {
	tag = strings.TrimSpace(tag)
	if inbound.ValidateIdentity(tag, 1) == nil {
		return tag
	}
	return "invalid-desired-inbound"
}

func (r *Reconciler) report(ctx context.Context, deployments []deploymentReport) error {
	supportedEngines := []string{}
	trustTunnelAvailable := r.trustTunnelApplyEnabled && r.trustTunnel != nil && r.trustTunnel.Available(ctx)
	if trustTunnelAvailable {
		supportedEngines = append(supportedEngines, "trusttunnel")
	}
	naiveAvailable := r.transportBundle != nil
	if naiveAvailable {
		supportedEngines = append(supportedEngines, "naiveproxy")
	}
	supportedProtocols := []string{}
	supportedTransports := []string{}
	if trustTunnelAvailable {
		supportedProtocols = append(supportedProtocols, "trusttunnel")
		supportedTransports = append(supportedTransports, "http2")
	}
	if naiveAvailable {
		supportedProtocols = append(supportedProtocols, "naive")
		if !trustTunnelAvailable {
			supportedTransports = append(supportedTransports, "http2")
		}
	}
	rawCapabilities, _ := json.Marshal(map[string]any{
		"controller_polling":       true,
		"controller_tag_namespace": "gx-",
		"durable_inventory":        true,
		"startup_reconciliation":   true,
		"desired_manifest_store":   true,
		"listener_networks":        []string{"tcp", "udp"},
		"udp_firewall_managed":     false,
		"udp_hop_external_dnat":    true,
		"trusttunnel_available":    trustTunnelAvailable,
		"naiveproxy_available":     naiveAvailable,
	})
	payload := observedReport{
		Capabilities: capabilitiesReport{
			AgentVersion:        sanitizeText(r.cfg.AgentVersion(), 128),
			CoreVersion:         "native",
			SupportedProtocols:  supportedProtocols,
			SupportedTransports: supportedTransports,
			SupportedSecurities: []string{"tls"},
			SupportedEngines:    supportedEngines,
			RawJSON:             rawCapabilities,
		},
		Deployments: deployments,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return errors.New("observed-state report could not be encoded")
	}
	if len(body) > maxReportBytes {
		return errors.New("observed-state report is too large")
	}
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, r.baseURL+"/v1/internal/node/inbounds/report", bytes.NewReader(body))
	if err != nil {
		return errors.New("build observed-state request failed")
	}
	r.setAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := r.http.Do(req)
	if err != nil {
		return errors.New("controller observed-state request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		drainResponse(resp.Body)
		return fmt.Errorf("controller observed-state returned HTTP %d", resp.StatusCode)
	}
	if _, err := readBounded(resp.Body, maxReportBytes); err != nil {
		return fmt.Errorf("controller observed-state response rejected: %w", err)
	}
	return nil
}

func (r *Reconciler) setAuthHeaders(req *http.Request) {
	req.Header.Set("X-Service-Token", r.cfg.InternalServiceToken)
	req.Header.Set("X-Node-Secret", r.cfg.Secret)
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, errors.New("response body could not be read")
	}
	if int64(len(body)) > limit {
		return nil, errors.New("response body exceeds limit")
	}
	return body, nil
}

func drainResponse(reader io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(reader, 4<<10))
}

func normalizeClientUUIDs(values []string) ([]string, string, error) {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if !uuidPattern.MatchString(value) {
			return nil, "", errors.New("client UUID set contains an invalid UUID")
		}
		unique[value] = struct{}{}
	}
	clients := make([]string, 0, len(unique))
	for value := range unique {
		clients = append(clients, value)
	}
	sort.Strings(clients)
	digest := sha256.Sum256([]byte(strings.Join(clients, "\n")))
	return clients, hex.EncodeToString(digest[:]), nil
}

func emptyClientSetHash() string {
	digest := sha256.Sum256(nil)
	return hex.EncodeToString(digest[:])
}

func sanitizeText(value string, max int) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	for _, character := range value {
		if character >= 0x20 && character != 0x7f {
			builder.WriteRune(character)
		}
		if builder.Len() >= max {
			break
		}
	}
	result := builder.String()
	if len(result) > max {
		result = result[:max]
	}
	return result
}

func (r *Reconciler) UUIDs() []string {
	r.inventoryMu.RLock()
	defer r.inventoryMu.RUnlock()
	var result []string
	for _, ids := range r.inventory {
		result = append(result, ids...)
	}
	return result
}
