// Package controller implements the outbound-only desired/observed control
// plane. Nodes poll the backend over verified HTTPS, reconcile a fully
// validated manifest, then report terminal state without exposing private
// Reality material.
package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/guardex/node-agent/internal/config"
	"github.com/guardex/node-agent/internal/inbound"
	"github.com/guardex/node-agent/internal/inboundsync"
	"github.com/guardex/node-agent/internal/store"
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
	clientCount     int
	clientSetSHA256 string
}

type deploymentReport struct {
	InboundID              string          `json:"inbound_id"`
	AppliedRevision        int64           `json:"applied_revision"`
	EffectiveTag           string          `json:"effective_tag"`
	EffectivePort          int             `json:"effective_port"`
	Status                 string          `json:"status"`
	PublicMaterialJSON     json.RawMessage `json:"public_material_json"`
	ClientParamsJSON       json.RawMessage `json:"client_params_json"`
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
	RawJSON             json.RawMessage `json:"raw_json"`
}

type observedReport struct {
	Capabilities capabilitiesReport `json:"capabilities"`
	Deployments  []deploymentReport `json:"deployments"`
}

// Reconciler owns no inbound state itself. The Manager remains the single
// serialized runtime/durable mutation boundary shared with legacy push routes.
type Reconciler struct {
	cfg      *config.Config
	manager  *inboundsync.Manager
	users    *store.Store
	userCore userCore
	http     *http.Client
	baseURL  string
	interval time.Duration
	userOps  *userops.Coordinator
}

type userCore interface {
	AddUser(context.Context, xray.AddUserParams) error
	RemoveUser(context.Context, string, string) error
	ListInboundUserIDs(context.Context, string) ([]string, error)
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

	reports := make([]deploymentReport, 0, len(prepared))
	failed := 0
	for _, item := range prepared {
		report := r.reconcileOne(ctx, item)
		if report.Status != "active" && report.Status != "deleted" {
			failed++
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
	ports := make(map[int]int, len(items))

	for index, item := range items {
		item.InboundID = strings.TrimSpace(item.InboundID)
		item.Action = strings.ToLower(strings.TrimSpace(item.Action))
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
		if item.EffectivePort == 443 {
			errorsByIndex[index] = itemError{"protected_port", "port 443 belongs to the static baseline inbound"}
			continue
		}
		if previous, duplicate := tags[item.EffectiveTag]; duplicate {
			errorsByIndex[index] = itemError{"duplicate_tag", "manifest contains a duplicate effective tag"}
			errorsByIndex[previous] = itemError{"duplicate_tag", "manifest contains a duplicate effective tag"}
		} else {
			tags[item.EffectiveTag] = index
		}
		if item.Action == "apply" {
			if previous, duplicate := ports[item.EffectivePort]; duplicate {
				errorsByIndex[index] = itemError{"duplicate_port", "manifest contains a duplicate effective port"}
				errorsByIndex[previous] = itemError{"duplicate_port", "manifest contains a duplicate effective port"}
			} else {
				ports[item.EffectivePort] = index
			}
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
	if protocol != "vless" {
		return preparedItem{}, errors.New("desired config is not VLESS")
	}
	root["tag"] = item.EffectiveTag
	root["port"] = item.EffectivePort

	settings, ok := root["settings"].(map[string]any)
	if !ok {
		return preparedItem{}, errors.New("desired VLESS settings are invalid")
	}
	// UUID membership is intentionally excluded from the structural config.
	// Client-only manifest changes are reconciled through AlterInbound and must
	// never recreate the handler or interrupt existing sessions.
	settings["clients"] = []any{}
	settings["decryption"] = "none"
	root["settings"] = settings

	keylessRaw, err := json.Marshal(root)
	if err != nil {
		return preparedItem{}, errors.New("desired config could not be normalized")
	}
	keyless, err := inbound.Parse(keylessRaw)
	if err != nil {
		return preparedItem{}, err
	}
	if keyless.Security != "reality" || (keyless.Network != "raw" && keyless.Network != "xhttp") {
		return preparedItem{}, errors.New("phase-1 controller supports only RAW/XHTTP with Reality")
	}
	if keyless.Network == "xhttp" && item.UserFlow != "" {
		return preparedItem{}, errors.New("XHTTP controller inbounds must not use a VLESS flow")
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
	publicMaterial, clientParams := safeConnectionMaterial(runtimeConfig.Raw, publicKey, shortID)
	return preparedItem{
		desired:         item,
		config:          runtimeConfig,
		desiredDigest:   keyless.Digest,
		publicMaterial:  publicMaterial,
		clientParams:    clientParams,
		clientCount:     len(clients),
		clientSetSHA256: clientHash,
	}, nil
}

func (r *Reconciler) reconcileOne(ctx context.Context, item preparedItem) deploymentReport {
	desired := item.desired
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
			AppliedClientSetSHA256: emptyClientSetHash(),
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
		AppliedClientCount:     currentCount,
		AppliedClientSetSHA256: currentHash,
	}
	structuralChanged, err := r.manager.ApplyControllerDesiredWithResult(ctx, item.config, item.desiredDigest, controllerState)
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
		return r.failedReportPreservingLKG(desired, itemError{code, message}, code != "stale_revision")
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
		AppliedClientCount:     item.clientCount,
		AppliedClientSetSHA256: item.clientSetSHA256,
	}
}

func (r *Reconciler) reconcileUsers(ctx context.Context, item preparedItem, structuralChanged bool) error {
	if r.users == nil || r.userCore == nil {
		return errors.New("user reconciliation is not configured")
	}
	desired := make(map[string]store.User, item.clientCount)
	for _, uuid := range item.desired.ClientUUIDs {
		uuid = strings.ToLower(strings.TrimSpace(uuid))
		desired[uuid] = store.User{UUID: uuid, InboundTag: item.desired.EffectiveTag, Flow: item.desired.UserFlow}
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
		if keep && persistedOK && persisted.Flow == wanted.Flow {
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
		if keep && wanted.Flow == persisted.Flow {
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
				Flow:       wanted.Flow,
			})
			if err != nil && !xray.IsAlreadyExists(err) {
				return err
			}
			runtime[uuid] = struct{}{}
		}
		if current, exists := existing[uuid]; !exists || current.Flow != wanted.Flow {
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
		if !ok || wanted.Flow != user.Flow {
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
	rawCapabilities, _ := json.Marshal(map[string]any{
		"controller_polling":       true,
		"controller_tag_namespace": "gx-",
		"durable_inventory":        true,
		"startup_reconciliation":   true,
		"desired_manifest_store":   true,
	})
	payload := observedReport{
		Capabilities: capabilitiesReport{
			AgentVersion:        sanitizeText(r.cfg.AgentVersion(), 128),
			CoreVersion:         sanitizeText(r.cfg.XrayCoreVersion, 128),
			SupportedProtocols:  []string{"vless"},
			SupportedTransports: []string{"raw", "xhttp"},
			SupportedSecurities: []string{"reality"},
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

func safeConnectionMaterial(raw []byte, publicKey, shortID string) (json.RawMessage, json.RawMessage) {
	public := make(map[string]any)
	client := make(map[string]any)
	if publicKey != "" {
		public["public_key"] = publicKey
	}
	if shortID != "" {
		public["short_id"] = shortID
	}
	var root struct {
		StreamSettings struct {
			Network             string         `json:"network"`
			RealitySettings     map[string]any `json:"realitySettings"`
			XHTTPSettings       map[string]any `json:"xhttpSettings"`
			SplitHTTPSettings   map[string]any `json:"splithttpSettings"`
			GRPCSettings        map[string]any `json:"grpcSettings"`
			WebSocketSettings   map[string]any `json:"wsSettings"`
			HTTPUpgradeSettings map[string]any `json:"httpupgradeSettings"`
			RawSettings         map[string]any `json:"rawSettings"`
			TCPSettings         map[string]any `json:"tcpSettings"`
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
		copyAllowedClientParams(client, root.StreamSettings.WebSocketSettings, "path", "host")
		copyAllowedClientParams(client, root.StreamSettings.HTTPUpgradeSettings, "path", "host")
		copyHeaderType(client, root.StreamSettings.RawSettings)
		copyHeaderType(client, root.StreamSettings.TCPSettings)
	}
	publicJSON, _ := json.Marshal(public)
	clientJSON, _ := json.Marshal(client)
	return publicJSON, clientJSON
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
