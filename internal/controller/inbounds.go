// Package controller implements the outbound-only desired/observed control
// plane. Nodes poll the backend over verified HTTPS, reconcile a fully
// validated manifest, then report terminal state without exposing private
// Reality material.
package controller

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/guardex/node-agent/internal/config"
	"github.com/guardex/node-agent/internal/inbound"
	"github.com/guardex/node-agent/internal/inboundsync"
	"github.com/guardex/node-agent/internal/store"
	"github.com/guardex/node-agent/internal/transportbundle"
	"github.com/guardex/node-agent/internal/trusttunnel"
	"github.com/guardex/node-agent/internal/userops"
	"github.com/guardex/node-agent/internal/xray"
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
	desired         desiredItem
	config          inbound.Config
	desiredDigest   string
	publicMaterial  json.RawMessage
	clientParams    json.RawMessage
	clientSecret    json.RawMessage
	refreshRuntime  bool
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

// Reconciler owns no inbound state itself. The Manager remains the single
// serialized runtime/durable mutation boundary shared with legacy push routes.
type Reconciler struct {
	cfg                     *config.Config
	manager                 *inboundsync.Manager
	users                   *store.Store
	userCore                userCore
	http                    *http.Client
	baseURL                 string
	interval                time.Duration
	userOps                 *userops.Coordinator
	trustTunnel             trustTunnelRuntime
	trustTunnelApplyEnabled bool
	transportBundle         transportBundleRuntime
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

type userCore interface {
	AddUser(context.Context, xray.AddUserParams) error
	RemoveUser(context.Context, string, string) error
	ListInboundUserIDs(context.Context, string) ([]string, error)
}

// EnableTrustTunnel adds the independent endpoint runtime. It is intentionally
// opt-in so older installations keep advertising and applying Xray only.
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

func New(cfg *config.Config, manager *inboundsync.Manager, users *store.Store, usersRuntime userCore, coordinators ...*userops.Coordinator) (*Reconciler, error) {
	if cfg == nil || manager == nil || users == nil || usersRuntime == nil {
		return nil, errors.New("controller reconciler requires config, inbound manager, user store, and user runtime")
	}
	if !cfg.ControllerPollingEnabled() {
		return nil, errors.New("controller polling requires a complete verified HTTPS configuration")
	}
	parsed, err := url.Parse(strings.TrimSpace(cfg.ControllerURL))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("controller URL must be a verified HTTPS origin")
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	coordinator := userops.New()
	if len(coordinators) > 0 && coordinators[0] != nil {
		coordinator = coordinators[0]
	}
	return &Reconciler{
		cfg:      cfg,
		manager:  manager,
		users:    users,
		userCore: usersRuntime,
		http:     &http.Client{Timeout: requestTimeout, CheckRedirect: rejectRedirect},
		baseURL:  strings.TrimRight(parsed.String(), "/"),
		interval: normalizedInterval(cfg.ResyncInterval),
		userOps:  coordinator,
	}, nil
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
	r.userOps.Lock()
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

	reports := make([]deploymentReport, 0, len(prepared))
	failed := 0
	for _, item := range prepared {
		report := r.reconcileOne(ctx, item)
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
			item.Engine = "xray"
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
		if item.Engine != "xray" && item.Engine != "trusttunnel" && item.Engine != "naiveproxy" {
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
		} else if item.trustTunnel == nil && item.config.Protocol == "hysteria" {
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
	for index, item := range prepared {
		itemErr, invalid := errorsByIndex[index]
		forceDegraded := invalid
		if !invalid {
			itemErr = itemError{"manifest_rejected", "manifest was not applied because another item is invalid"}
		}
		if item.desired.InboundID == "" {
			continue
		}
		reports = append(reports, r.failedReportPreservingLKG(item.desired, itemErr, forceDegraded))
	}
	return nil, reports, errors.New("controller manifest failed whole-manifest validation")
}

func (r *Reconciler) prepareApply(item desiredItem) (preparedItem, error) {
	if item.UserFlow != "" && item.UserFlow != "xtls-rprx-vision" {
		return preparedItem{}, errors.New("unsupported VLESS flow")
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

	var root map[string]any
	decoder := json.NewDecoder(bytes.NewReader(item.ConfigJSON))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil || root == nil {
		return preparedItem{}, errors.New("desired config must be a JSON object")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return preparedItem{}, errors.New("desired config contains trailing data")
	}
	if err := rejectControllerKeyMaterial(root); err != nil {
		return preparedItem{}, err
	}
	protocol, _ := root["protocol"].(string)
	if protocol != "vless" && protocol != "hysteria" {
		return preparedItem{}, errors.New("desired config protocol is unsupported")
	}
	root["tag"] = item.EffectiveTag
	root["port"] = item.EffectivePort

	settings, ok := root["settings"].(map[string]any)
	if !ok {
		return preparedItem{}, errors.New("desired protocol settings are invalid")
	}
	// UUID membership is intentionally excluded from the structural config.
	// Client-only manifest changes are reconciled through AlterInbound and must
	// never recreate the handler or interrupt existing sessions.
	settings["clients"] = []any{}
	if protocol == "vless" {
		settings["decryption"] = "none"
	} else {
		settings["version"] = json.Number("2")
		delete(settings, "users")
	}
	root["settings"] = settings
	desiredRaw, err := json.Marshal(root)
	if err != nil {
		return preparedItem{}, errors.New("desired config could not be normalized")
	}
	desiredConfig, err := inbound.Parse(desiredRaw)
	if err != nil {
		return preparedItem{}, err
	}
	if err := secureForwardedFor(root, r.cfg.Secret); err != nil {
		return preparedItem{}, err
	}

	keylessRaw, err := json.Marshal(root)
	if err != nil {
		return preparedItem{}, errors.New("desired config could not be normalized")
	}
	keyless, err := inbound.Parse(keylessRaw)
	if err != nil {
		return preparedItem{}, err
	}
	if keyless.Protocol == "vless" {
		if keyless.Security != "reality" || (keyless.Network != "raw" && keyless.Network != "xhttp" && keyless.Network != "grpc") {
			return preparedItem{}, errors.New("controller VLESS supports only RAW/XHTTP/gRPC with Reality")
		}
		if (keyless.Network == "xhttp" || keyless.Network == "grpc") && item.UserFlow != "" {
			return preparedItem{}, fmt.Errorf("%s controller inbounds must not use a VLESS flow", strings.ToUpper(keyless.Network))
		}
	} else if item.UserFlow != "" {
		return preparedItem{}, errors.New("Hysteria controller inbounds must not use a VLESS flow")
	}
	if keyless.Protocol == "hysteria" {
		// Realize node-local TLS/Salamander material only after the complete
		// manifest passes validation. This prevents an unrelated invalid item
		// from rotating disk material without the matching runtime refresh/report.
		return preparedItem{
			desired:         item,
			config:          keyless,
			desiredDigest:   desiredConfig.Digest,
			publicMaterial:  json.RawMessage(`{}`),
			clientParams:    json.RawMessage(`{}`),
			clientSecret:    json.RawMessage(`{}`),
			clientCount:     len(clients),
			clientSetSHA256: clientHash,
		}, nil
	}
	previousRaw := []byte(nil)
	if previous, ok := r.manager.ManagedConfig(item.EffectiveTag); ok {
		previousRaw = previous.Raw
	}
	runtimeRaw, publicKey, shortID, err := xray.EnsureRealityKey(keyless.Raw, previousRaw)
	if err != nil {
		return preparedItem{}, err
	}
	runtimeConfig, err := inbound.Parse(runtimeRaw)
	if err != nil {
		return preparedItem{}, err
	}
	if err := xray.ValidateInboundForCore(runtimeConfig.Raw); err != nil {
		return preparedItem{}, errors.New("desired config is unsupported by the running core")
	}
	publicMaterial, clientParams, clientSecret := safeConnectionMaterial(runtimeConfig.Raw, publicKey, shortID, xray.HysteriaMaterial{})
	return preparedItem{
		desired:         item,
		config:          runtimeConfig,
		desiredDigest:   desiredConfig.Digest,
		publicMaterial:  publicMaterial,
		clientParams:    clientParams,
		clientSecret:    clientSecret,
		clientCount:     len(clients),
		clientSetSHA256: clientHash,
	}, nil
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
	return preparedItem{desired: item, desiredDigest: hex.EncodeToString(digest[:]), publicMaterial: json.RawMessage(`{}`), clientParams: json.RawMessage(`{}`), clientSecret: json.RawMessage(`{}`), clientCount: len(clients), clientSetSHA256: clientHash, transportBundle: &bundle}, nil
}

// secureForwardedFor prevents HTTP transports from accepting a forged
// X-Forwarded-For value on their public listener. Xray only honors that value
// when one of the configured marker headers is also present. The marker is
// derived from the node-local secret, is never published to clients, and is
// therefore suitable for direct listeners that do not sit behind a trusted
// reverse proxy.
func secureForwardedFor(root map[string]any, nodeSecret string) error {
	stream, ok := root["streamSettings"].(map[string]any)
	if !ok {
		return errors.New("desired stream settings are invalid")
	}
	network, _ := stream["network"].(string)
	if network != "xhttp" && network != "grpc" {
		return nil
	}

	sockopt := map[string]any{}
	if existing, exists := stream["sockopt"]; exists {
		var valid bool
		sockopt, valid = existing.(map[string]any)
		if !valid {
			return errors.New("desired socket settings are invalid")
		}
	}
	mac := hmac.New(sha256.New, []byte(strings.TrimSpace(nodeSecret)))
	_, _ = mac.Write([]byte("guardex/xray/trusted-forwarded-for/v1"))
	marker := "X-Guardex-Trusted-" + hex.EncodeToString(mac.Sum(nil)[:12])
	sockopt["trustedXForwardedFor"] = []any{marker}
	stream["sockopt"] = sockopt
	root["streamSettings"] = stream
	return nil
}

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
	return preparedItem{desired: item, desiredDigest: hex.EncodeToString(digest[:]), publicMaterial: json.RawMessage(`{}`), clientParams: json.RawMessage(`{}`), clientSecret: json.RawMessage(`{}`), clientCount: len(clients), clientSetSHA256: clientHash, trustTunnel: &endpoint}, nil
}

func (r *Reconciler) realizeManagedHysteria(item preparedItem) (preparedItem, error) {
	previousRaw := []byte(nil)
	if previous, ok := r.manager.ManagedConfig(item.desired.EffectiveTag); ok {
		previousRaw = previous.Raw
	}
	runtimeRaw, material, err := xray.EnsureManagedHysteriaMaterial(item.config.Raw, previousRaw)
	if err != nil {
		return item, err
	}
	runtimeConfig, err := inbound.Parse(runtimeRaw)
	if err != nil {
		return item, err
	}
	publicMaterial, clientParams, clientSecret := safeConnectionMaterial(runtimeConfig.Raw, "", "", material)
	item.config = runtimeConfig
	item.publicMaterial = publicMaterial
	item.clientParams = clientParams
	item.clientSecret = clientSecret
	item.refreshRuntime = material.CertificateRotated || r.durableHysteriaPinDiffers(item.desired.EffectiveTag, material.PinSHA256)
	if err := xray.ValidateInboundForCore(runtimeConfig.Raw); err != nil {
		return item, errors.New("desired config is unsupported by the running core")
	}
	return item, nil
}

func (r *Reconciler) durableHysteriaPinDiffers(tag, pin string) bool {
	state, ok := r.manager.ControllerState(tag)
	if !ok || pin == "" {
		return false
	}
	var params struct {
		PinSHA256 string `json:"pin_sha256"`
	}
	if json.Unmarshal(state.ClientParamsJSON, &params) != nil || params.PinSHA256 == "" {
		return false
	}
	return !strings.EqualFold(params.PinSHA256, pin)
}

func (r *Reconciler) reconcileOne(ctx context.Context, item preparedItem) deploymentReport {
	desired := item.desired
	if desired.Engine == "trusttunnel" {
		return r.reconcileTrustTunnel(ctx, item)
	}
	if desired.Engine == "naiveproxy" {
		return r.reconcileNaiveProxy(ctx, item)
	}
	if desired.Action == "delete" {
		previousRevision := r.previousRevision(desired.EffectiveTag, desired.InboundID)
		if err := r.manager.RemoveControllerDesired(ctx, desired.EffectiveTag, desired.InboundID, desired.DesiredRevision); err != nil {
			code := "delete_failed"
			message := "node could not remove the managed inbound"
			if errors.Is(err, inboundsync.ErrNotManaged) || errors.Is(err, inboundsync.ErrControllerOwnership) {
				code = "protected_inbound"
				message = "tombstone does not own this dynamic inbound"
			}
			if errors.Is(err, inboundsync.ErrStaleRevision) {
				code, message = "stale_revision", "tombstone is older than the node's durable desired state"
			}
			if errors.Is(err, inboundsync.ErrRevisionConflict) {
				code, message = "revision_conflict", "tombstone changed desired action without incrementing revision"
			}
			return r.failedReportPreservingLKG(desired, itemError{code, message}, code != "stale_revision")
		}
		if r.users != nil {
			if err := r.users.RemoveByInboundTag(desired.EffectiveTag); err != nil {
				return failedReport(desired, previousRevision, itemError{"user_store_cleanup_failed", "managed inbound was removed but stale user cleanup must be retried"})
			}
		}
		return deploymentReport{
			InboundID:              desired.InboundID,
			AppliedRevision:        desired.DesiredRevision,
			EffectiveTag:           desired.EffectiveTag,
			EffectivePort:          desired.EffectivePort,
			Status:                 "deleted",
			PublicMaterialJSON:     json.RawMessage(`{}`),
			ClientParamsJSON:       json.RawMessage(`{}`),
			ClientSecretJSON:       json.RawMessage(`{}`),
			AppliedClientSetSHA256: emptyClientSetHash(),
		}
	}
	if item.config.Protocol == "hysteria" {
		var err error
		item, err = r.realizeManagedHysteria(item)
		if err != nil {
			return r.failedPreparedReport(item, itemError{"material_realization_failed", "node could not realize the managed Hysteria material"}, true)
		}
	}

	currentCount, currentHash := r.currentClientSet(desired.EffectiveTag)
	controllerState := store.InboundControllerState{
		InboundID:              desired.InboundID,
		DesiredRevision:        desired.DesiredRevision,
		AppliedRevision:        desired.DesiredRevision,
		Status:                 "degraded",
		PublicMaterialJSON:     item.publicMaterial,
		ClientParamsJSON:       item.clientParams,
		ClientSecretJSON:       item.clientSecret,
		AppliedClientCount:     currentCount,
		AppliedClientSetSHA256: currentHash,
	}
	structuralChanged, err := r.manager.ApplyControllerDesiredWithRefresh(ctx, item.config, item.desiredDigest, controllerState, item.refreshRuntime)
	if err != nil {
		code := "apply_failed"
		message := "node could not apply the desired inbound"
		switch {
		case errors.Is(err, inboundsync.ErrTagConflict):
			code, message = "tag_conflict", "desired tag conflicts with an unmanaged runtime inbound"
		case errors.Is(err, inboundsync.ErrControllerOwnership):
			code, message = "ownership_conflict", "desired tag belongs to another catalogue identity"
		case errors.Is(err, inboundsync.ErrStaleRevision):
			code, message = "stale_revision", "desired apply is older than the node's durable desired state"
		case errors.Is(err, inboundsync.ErrRevisionConflict):
			code, message = "revision_conflict", "structural desired state changed without incrementing revision"
		}
		if item.refreshRuntime && code == "apply_failed" {
			code = "certificate_reload_failed"
			message = "node rotated managed TLS material but the immediate handler reload requires retry"
		}
		if item.refreshRuntime {
			// A failed forced reload may have restored the structural handler with
			// settings.clients=[]; immediately rebuild users from the desired/durable
			// snapshot. If no handler exists, reconcileUsers returns before deleting
			// that durable snapshot, so the next poll can retry safely.
			_ = r.reconcileUsers(ctx, item, false)
		}
		return r.failedPreparedReport(item, itemError{code, message}, code != "stale_revision")
	}
	if err := r.reconcileUsers(ctx, item, structuralChanged); err != nil {
		actualCount, actualHash := r.currentClientSet(desired.EffectiveTag)
		degraded := controllerState
		degraded.AppliedClientCount = actualCount
		degraded.AppliedClientSetSHA256 = actualHash
		_ = r.manager.UpdateControllerState(desired.EffectiveTag, degraded)
		return deploymentReport{
			InboundID:              desired.InboundID,
			AppliedRevision:        desired.DesiredRevision,
			EffectiveTag:           desired.EffectiveTag,
			EffectivePort:          desired.EffectivePort,
			Status:                 "degraded",
			PublicMaterialJSON:     item.publicMaterial,
			ClientParamsJSON:       item.clientParams,
			ClientSecretJSON:       item.clientSecret,
			AppliedClientCount:     actualCount,
			AppliedClientSetSHA256: actualHash,
			ErrorCode:              "client_reconcile_incomplete",
			ErrorMessage:           "structural inbound is active but the exact client set requires retry",
		}
	}
	controllerState.Status = "active"
	controllerState.AppliedClientCount = item.clientCount
	controllerState.AppliedClientSetSHA256 = item.clientSetSHA256
	if err := r.manager.UpdateControllerState(desired.EffectiveTag, controllerState); err != nil {
		if errors.Is(err, inboundsync.ErrStaleRevision) || errors.Is(err, inboundsync.ErrControllerOwnership) || errors.Is(err, inboundsync.ErrRevisionConflict) {
			return r.failedReportPreservingLKG(desired, itemError{"observed_state_superseded", "a newer controller operation superseded this reconciliation"}, false)
		}
		return deploymentReport{
			InboundID:              desired.InboundID,
			AppliedRevision:        desired.DesiredRevision,
			EffectiveTag:           desired.EffectiveTag,
			EffectivePort:          desired.EffectivePort,
			Status:                 "degraded",
			PublicMaterialJSON:     item.publicMaterial,
			ClientParamsJSON:       item.clientParams,
			ClientSecretJSON:       item.clientSecret,
			AppliedClientCount:     item.clientCount,
			AppliedClientSetSHA256: item.clientSetSHA256,
			ErrorCode:              "observed_state_persist_failed",
			ErrorMessage:           "runtime is active but durable observed state requires retry",
		}
	}
	return deploymentReport{
		InboundID:              desired.InboundID,
		AppliedRevision:        desired.DesiredRevision,
		EffectiveTag:           desired.EffectiveTag,
		EffectivePort:          desired.EffectivePort,
		Status:                 "active",
		PublicMaterialJSON:     item.publicMaterial,
		ClientParamsJSON:       item.clientParams,
		ClientSecretJSON:       item.clientSecret,
		AppliedClientCount:     item.clientCount,
		AppliedClientSetSHA256: item.clientSetSHA256,
	}
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
	return deploymentReport{InboundID: desired.InboundID, AppliedRevision: state.Revision, EffectiveTag: desired.EffectiveTag, EffectivePort: desired.EffectivePort, Status: "active", PublicMaterialJSON: json.RawMessage(`{}`), ClientParamsJSON: json.RawMessage(`{}`), ClientSecretJSON: json.RawMessage(`{}`), AppliedClientCount: state.ClientCount, AppliedClientSetSHA256: state.ClientSetSHA256}
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
	return deploymentReport{InboundID: desired.InboundID, AppliedRevision: state.Revision, EffectiveTag: desired.EffectiveTag, EffectivePort: desired.EffectivePort, Status: "active", PublicMaterialJSON: json.RawMessage(`{}`), ClientParamsJSON: json.RawMessage(`{}`), ClientSecretJSON: json.RawMessage(`{}`), AppliedClientCount: state.ClientCount, AppliedClientSetSHA256: state.ClientSetSHA256}
}

func (r *Reconciler) reconcileUsers(ctx context.Context, item preparedItem, structuralChanged bool) error {
	if r.users == nil || r.userCore == nil {
		return errors.New("user reconciliation is not configured")
	}
	desired := make(map[string]store.User, item.clientCount)
	for _, uuid := range item.desired.ClientUUIDs {
		uuid = strings.ToLower(strings.TrimSpace(uuid))
		desired[uuid] = store.User{UUID: uuid, InboundTag: item.desired.EffectiveTag, Protocol: item.config.Protocol, Flow: item.desired.UserFlow}
	}

	if structuralChanged {
		// A new handler starts with settings.clients=[] regardless of the old
		// durable user inventory. Clear the tag snapshot first so partial AddUser
		// progress is represented exactly and the next poll retries every miss.
		if err := r.users.RemoveByInboundTag(item.desired.EffectiveTag); err != nil {
			return err
		}
	}
	existing := make(map[string]store.User)
	for _, user := range r.users.UsersByInboundTag(item.desired.EffectiveTag) {
		existing[strings.ToLower(strings.TrimSpace(user.UUID))] = user
	}
	runtimeIDs, err := r.userCore.ListInboundUserIDs(ctx, item.desired.EffectiveTag)
	if err != nil {
		return err
	}
	runtime := make(map[string]struct{}, len(runtimeIDs))
	for _, uuid := range runtimeIDs {
		uuid = strings.ToLower(strings.TrimSpace(uuid))
		if uuid != "" {
			runtime[uuid] = struct{}{}
		}
	}

	// Remove every runtime UUID not desired, plus users whose global flow has
	// changed. Durable-only extras are removed below without an unnecessary RPC.
	for uuid := range runtime {
		wanted, keep := desired[uuid]
		persisted, persistedOK := existing[uuid]
		if keep && persistedOK && persisted.Flow == wanted.Flow && normalizedUserProtocol(persisted.Protocol) == normalizedUserProtocol(wanted.Protocol) {
			continue
		}
		if err := r.userCore.RemoveUser(ctx, item.desired.EffectiveTag, uuid); err != nil && !xray.IsNotFound(err) {
			return err
		}
		if err := r.users.Remove(item.desired.EffectiveTag, uuid); err != nil {
			return err
		}
		delete(existing, uuid)
		delete(runtime, uuid)
	}
	for uuid, persisted := range existing {
		wanted, keep := desired[uuid]
		if keep && wanted.Flow == persisted.Flow && normalizedUserProtocol(wanted.Protocol) == normalizedUserProtocol(persisted.Protocol) {
			continue
		}
		if err := r.users.Remove(item.desired.EffectiveTag, persisted.UUID); err != nil {
			return err
		}
		delete(existing, uuid)
	}
	for uuid, wanted := range desired {
		if _, exists := runtime[uuid]; !exists {
			err := r.userCore.AddUser(ctx, xray.AddUserParams{
				InboundTag: item.desired.EffectiveTag,
				UUID:       wanted.UUID,
				Protocol:   wanted.Protocol,
				Flow:       wanted.Flow,
			})
			if err != nil && !xray.IsAlreadyExists(err) {
				return err
			}
			runtime[uuid] = struct{}{}
		}
		if current, exists := existing[uuid]; !exists || current.Flow != wanted.Flow || normalizedUserProtocol(current.Protocol) != normalizedUserProtocol(wanted.Protocol) {
			if err := r.users.Add(wanted); err != nil {
				return err
			}
		}
	}

	runtimeIDs, err = r.userCore.ListInboundUserIDs(ctx, item.desired.EffectiveTag)
	if err != nil {
		return err
	}
	runtime = make(map[string]struct{}, len(runtimeIDs))
	for _, uuid := range runtimeIDs {
		runtime[strings.ToLower(strings.TrimSpace(uuid))] = struct{}{}
	}
	if len(runtime) != len(desired) {
		return errors.New("runtime client set count mismatch")
	}
	for uuid := range desired {
		if _, ok := runtime[uuid]; !ok {
			return errors.New("runtime client set mismatch")
		}
	}
	actual := r.users.UsersByInboundTag(item.desired.EffectiveTag)
	if len(actual) != len(desired) {
		return errors.New("durable client set count mismatch")
	}
	for _, user := range actual {
		wanted, ok := desired[strings.ToLower(strings.TrimSpace(user.UUID))]
		if !ok || wanted.Flow != user.Flow || normalizedUserProtocol(wanted.Protocol) != normalizedUserProtocol(user.Protocol) {
			return errors.New("durable client set mismatch")
		}
	}
	return nil
}

func (r *Reconciler) currentClientSet(tag string) (int, string) {
	if r.users == nil {
		return 0, emptyClientSetHash()
	}
	users := r.users.UsersByInboundTag(tag)
	uuids := make([]string, 0, len(users))
	for _, user := range users {
		uuid := strings.ToLower(strings.TrimSpace(user.UUID))
		if uuidPattern.MatchString(uuid) {
			uuids = append(uuids, uuid)
		}
	}
	clients, digest, err := normalizeClientUUIDs(uuids)
	if err != nil {
		return 0, emptyClientSetHash()
	}
	return len(clients), digest
}

func (r *Reconciler) previousRevision(tag, inboundID string) int64 {
	state, ok := r.manager.ControllerState(tag)
	if !ok || state.InboundID != inboundID {
		return 0
	}
	return state.AppliedRevision
}

func (r *Reconciler) failedPreparedReport(item preparedItem, problem itemError, forceDegraded bool) deploymentReport {
	report := r.failedReportPreservingLKG(item.desired, problem, forceDegraded)
	if item.config.Protocol != "hysteria" || !item.refreshRuntime {
		return report
	}
	// The atomic bundle is already the only certificate/key source and Xray's
	// paths resolve to it. Never report the old durable pin after a successful
	// on-disk rotation, even when the immediate handler reload degraded; the
	// next retry uses the pin difference to force another reload.
	report.PublicMaterialJSON = jsonObjectOrEmpty(item.publicMaterial)
	report.ClientParamsJSON = jsonObjectOrEmpty(item.clientParams)
	report.ClientSecretJSON = jsonObjectOrEmpty(item.clientSecret)
	report.AppliedClientCount, report.AppliedClientSetSHA256 = r.currentClientSet(item.desired.EffectiveTag)
	return report
}

func (r *Reconciler) failedReportPreservingLKG(item desiredItem, problem itemError, forceDegraded bool) deploymentReport {
	if state, ok := r.manager.ControllerState(item.EffectiveTag); ok && state.InboundID == item.InboundID {
		port := item.EffectivePort
		if cfg, exists := r.manager.ManagedConfig(item.EffectiveTag); exists {
			port = cfg.Port
		}
		status := state.Status
		if status != "active" && status != "degraded" && status != "failed" {
			status = "degraded"
		}
		// Invalid desired data only degrades a last-known-good deployment when it
		// is at least as new as the durable structural revision. A delayed broken
		// manifest must not erase the healthy observation for a newer apply.
		if (forceDegraded && item.DesiredRevision >= state.DesiredRevision) || state.AppliedRevision < item.DesiredRevision {
			status = "degraded"
		}
		report := deploymentReport{
			InboundID:              item.InboundID,
			AppliedRevision:        state.AppliedRevision,
			EffectiveTag:           item.EffectiveTag,
			EffectivePort:          port,
			Status:                 status,
			PublicMaterialJSON:     jsonObjectOrEmpty(state.PublicMaterialJSON),
			ClientParamsJSON:       jsonObjectOrEmpty(state.ClientParamsJSON),
			ClientSecretJSON:       jsonObjectOrEmpty(state.ClientSecretJSON),
			AppliedClientCount:     state.AppliedClientCount,
			AppliedClientSetSHA256: state.AppliedClientSetSHA256,
		}
		if status != "active" {
			report.ErrorCode = sanitizeText(problem.code, 128)
			report.ErrorMessage = sanitizeText(problem.message, 512)
		}
		if report.AppliedClientSetSHA256 == "" {
			report.AppliedClientSetSHA256 = emptyClientSetHash()
		}
		return report
	}
	if tombstone, ok := r.manager.ControllerTombstone(item.EffectiveTag); ok && tombstone.InboundID == item.InboundID {
		return deploymentReport{
			InboundID:              item.InboundID,
			AppliedRevision:        tombstone.DesiredRevision,
			EffectiveTag:           item.EffectiveTag,
			EffectivePort:          normalizedReportPort(item.EffectivePort),
			Status:                 "deleted",
			PublicMaterialJSON:     json.RawMessage(`{}`),
			ClientParamsJSON:       json.RawMessage(`{}`),
			ClientSecretJSON:       json.RawMessage(`{}`),
			AppliedClientSetSHA256: emptyClientSetHash(),
		}
	}
	return failedReport(item, r.previousRevision(item.EffectiveTag, item.InboundID), problem)
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
	supportedEngines := []string{"xray"}
	trustTunnelAvailable := r.trustTunnelApplyEnabled && r.trustTunnel != nil && r.trustTunnel.Available(ctx)
	if trustTunnelAvailable {
		supportedEngines = append(supportedEngines, "trusttunnel")
	}
	naiveAvailable := r.transportBundle != nil
	if naiveAvailable {
		supportedEngines = append(supportedEngines, "naiveproxy")
	}
	supportedProtocols := []string{"vless", "hysteria"}
	supportedTransports := []string{"raw", "xhttp", "grpc", "hysteria"}
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
		"hysteria_version":         2,
		"hysteria_tls_mode":        "node_local_pinned_self_signed",
		"hysteria_tls_root":        inbound.ManagedTLSRoot(),
		"hysteria_salamander":      true,
		"udp_firewall_managed":     false,
		"udp_hop_external_dnat":    true,
		"trusttunnel_available":    trustTunnelAvailable,
		"naiveproxy_available":     naiveAvailable,
	})
	payload := observedReport{
		Capabilities: capabilitiesReport{
			AgentVersion:        sanitizeText(r.cfg.AgentVersion(), 128),
			CoreVersion:         sanitizeText(r.cfg.XrayCoreVersion, 128),
			SupportedProtocols:  supportedProtocols,
			SupportedTransports: supportedTransports,
			SupportedSecurities: []string{"reality", "tls"},
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

func normalizedUserProtocol(protocol string) string {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		return "vless"
	}
	return protocol
}

func rejectControllerKeyMaterial(value any) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			var normalized strings.Builder
			for _, character := range strings.ToLower(key) {
				if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
					normalized.WriteRune(character)
				}
			}
			switch normalized.String() {
			case "privatekey", "privatekeyfile", "shortids":
				return errors.New("controller Reality key material must be generated by the node")
			case "certificate", "key":
				return errors.New("controller must use node-local TLS file references, not literal key material")
			case "password":
				if secret, ok := child.(string); ok && strings.TrimSpace(secret) != "" {
					return errors.New("controller Salamander material must be generated by the node")
				}
			}
			if err := rejectControllerKeyMaterial(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := rejectControllerKeyMaterial(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func safeConnectionMaterial(raw []byte, publicKey, shortID string, hysteriaMaterial xray.HysteriaMaterial) (json.RawMessage, json.RawMessage, json.RawMessage) {
	public := make(map[string]any)
	client := make(map[string]any)
	secret := make(map[string]any)
	if publicKey != "" {
		public["public_key"] = publicKey
	}
	if shortID != "" {
		public["short_id"] = shortID
	}
	var root struct {
		Protocol       string `json:"protocol"`
		StreamSettings struct {
			Network     string `json:"network"`
			TLSSettings struct {
				ServerName  string   `json:"serverName"`
				ALPN        []string `json:"alpn"`
				Fingerprint string   `json:"fingerprint"`
			} `json:"tlsSettings"`
			RealitySettings     map[string]any `json:"realitySettings"`
			XHTTPSettings       map[string]any `json:"xhttpSettings"`
			SplitHTTPSettings   map[string]any `json:"splithttpSettings"`
			GRPCSettings        map[string]any `json:"grpcSettings"`
			WebSocketSettings   map[string]any `json:"wsSettings"`
			HTTPUpgradeSettings map[string]any `json:"httpupgradeSettings"`
			RawSettings         map[string]any `json:"rawSettings"`
			TCPSettings         map[string]any `json:"tcpSettings"`
			FinalMask           struct {
				QuicParams struct {
					UDPHop struct {
						Ports    json.RawMessage `json:"ports"`
						Interval json.RawMessage `json:"interval"`
					} `json:"udpHop"`
				} `json:"quicParams"`
			} `json:"finalmask"`
		} `json:"streamSettings"`
	}
	if json.Unmarshal(raw, &root) == nil {
		if names, ok := root.StreamSettings.RealitySettings["serverNames"].([]any); ok && len(names) > 0 {
			if name, ok := names[0].(string); ok && name != "" {
				public["sni"] = name
			}
		}
		settings := root.StreamSettings.XHTTPSettings
		if len(settings) == 0 {
			settings = root.StreamSettings.SplitHTTPSettings
		}
		copyAllowedClientParams(client, settings, "path", "mode", "host")
		copyAllowedClientParams(client, root.StreamSettings.GRPCSettings, "serviceName", "authority")
		if multiMode, ok := root.StreamSettings.GRPCSettings["multiMode"].(bool); ok && multiMode {
			client["mode"] = "multi"
		}
		copyAllowedClientParams(client, root.StreamSettings.WebSocketSettings, "path", "host")
		copyAllowedClientParams(client, root.StreamSettings.HTTPUpgradeSettings, "path", "host")
		copyHeaderType(client, root.StreamSettings.RawSettings)
		copyHeaderType(client, root.StreamSettings.TCPSettings)
		if root.Protocol == "hysteria" {
			client["sni"] = root.StreamSettings.TLSSettings.ServerName
			if len(root.StreamSettings.TLSSettings.ALPN) > 0 {
				client["alpn"] = root.StreamSettings.TLSSettings.ALPN[0]
			}
			fingerprint := root.StreamSettings.TLSSettings.Fingerprint
			if fingerprint == "" {
				fingerprint = "chrome"
			}
			client["fingerprint"] = fingerprint
			client["pin_sha256"] = hysteriaMaterial.PinSHA256
			if value := canonicalScalar(root.StreamSettings.FinalMask.QuicParams.UDPHop.Ports); value != "" {
				client["udp_hop_ports"] = value
			}
			if value := canonicalScalar(root.StreamSettings.FinalMask.QuicParams.UDPHop.Interval); value != "" {
				client["udp_hop_interval"] = value
			}
			secret["salamander_password"] = hysteriaMaterial.SalamanderPassword
		}
	}
	publicJSON, _ := json.Marshal(public)
	clientJSON, _ := json.Marshal(client)
	secretJSON, _ := json.Marshal(secret)
	return publicJSON, clientJSON, secretJSON
}

func canonicalScalar(raw json.RawMessage) string {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strings.TrimSpace(text)
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		return number.String()
	}
	return ""
}

func copyAllowedClientParams(target, source map[string]any, keys ...string) {
	for _, key := range keys {
		if value, ok := source[key]; ok {
			switch value.(type) {
			case string, []any:
				target[key] = value
			}
		}
	}
}

func copyHeaderType(target, source map[string]any) {
	header, _ := source["header"].(map[string]any)
	if kind, ok := header["type"].(string); ok && kind != "" {
		target["header_type"] = kind
	}
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
