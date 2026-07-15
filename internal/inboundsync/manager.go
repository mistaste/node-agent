// Package inboundsync reconciles the durable dynamic-inbound desired state into
// Xray. It never enumerates or deletes config-file-managed inbounds.
package inboundsync

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/guardex/node-agent/internal/inbound"
	"github.com/guardex/node-agent/internal/store"
	"github.com/guardex/node-agent/internal/xray"
)

var (
	ErrTagConflict         = errors.New("inbound tag already exists outside the dynamic inventory")
	ErrNotManaged          = errors.New("inbound is not managed by the dynamic inventory")
	ErrControllerOwnership = store.ErrControllerOwnership
	ErrControllerOwned     = store.ErrControllerOwned
	ErrStaleRevision       = store.ErrControllerStaleRevision
	ErrRevisionConflict    = store.ErrControllerRevisionConflict
)

type Core interface {
	AddInboundFromJSON(context.Context, []byte) error
	RemoveInbound(context.Context, string) error
	ListInboundTags(context.Context) ([]string, error)
}

type Item struct {
	inbound.PublicConfig
	DesiredDigest          string    `json:"desired_digest"`
	InboundID              string    `json:"inbound_id,omitempty"`
	DesiredRevision        int64     `json:"desired_revision,omitempty"`
	AppliedRevision        int64     `json:"applied_revision,omitempty"`
	ControllerStatus       string    `json:"controller_status,omitempty"`
	AppliedClientCount     int       `json:"applied_client_count,omitempty"`
	AppliedClientSetSHA256 string    `json:"applied_client_set_sha256,omitempty"`
	Desired                bool      `json:"desired"`
	Applied                bool      `json:"applied"`
	UpdatedAt              time.Time `json:"updated_at"`
	LastAttempt            time.Time `json:"last_attempt,omitempty"`
	LastError              string    `json:"last_error,omitempty"`
}

type state struct {
	digest      string
	applied     bool
	lastAttempt time.Time
	lastError   string
}

type Manager struct {
	core     Core
	store    *store.InboundStore
	interval time.Duration

	operations sync.Mutex
	stateMu    sync.RWMutex
	states     map[string]state
	protected  map[string]struct{}
}

func New(core Core, inventory *store.InboundStore, interval time.Duration, protectedTags ...string) *Manager {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	manager := &Manager{
		core:      core,
		store:     inventory,
		interval:  interval,
		states:    make(map[string]state),
		protected: make(map[string]struct{}, len(protectedTags)),
	}
	for _, tag := range protectedTags {
		if tag != "" {
			manager.protected[tag] = struct{}{}
		}
	}
	return manager
}

// Apply realizes one desired config and then durably records it. Repeating the
// same config is safe. Replacing a managed tag rolls back to the prior runtime
// config if either the new Xray config or durable write fails.
func (m *Manager) Apply(ctx context.Context, cfg inbound.Config) error {
	return m.ApplyDesired(ctx, cfg, cfg.Digest)
}

func (m *Manager) ApplyDesired(ctx context.Context, cfg inbound.Config, desiredDigest string) error {
	_, err := m.applyDesired(ctx, cfg, desiredDigest, store.InboundControllerState{})
	return err
}

// ApplyControllerDesired realizes and persists one versioned controller item.
// A v1/manual record can be adopted, but once associated with an inbound_id the
// same tag cannot be reassigned to a different catalogue identity.
func (m *Manager) ApplyControllerDesired(ctx context.Context, cfg inbound.Config, desiredDigest string, controller store.InboundControllerState) error {
	_, err := m.ApplyControllerDesiredWithResult(ctx, cfg, desiredDigest, controller)
	return err
}

// ApplyControllerDesiredWithResult reports whether the structural handler was
// recreated. The controller uses this to re-add the exact desired UUID set only
// when Xray necessarily lost its in-memory users.
func (m *Manager) ApplyControllerDesiredWithResult(ctx context.Context, cfg inbound.Config, desiredDigest string, controller store.InboundControllerState) (bool, error) {
	if controller.InboundID == "" {
		return false, errors.New("controller inbound id is required")
	}
	return m.applyDesired(ctx, cfg, desiredDigest, controller)
}

func (m *Manager) applyDesired(ctx context.Context, cfg inbound.Config, desiredDigest string, controller store.InboundControllerState) (bool, error) {
	validated, err := inbound.Parse(cfg.Raw)
	if err != nil {
		return false, fmt.Errorf("validate inbound before apply: %w", err)
	}
	cfg = validated
	if m.isProtected(cfg.Tag) {
		return false, ErrTagConflict
	}
	if controller.InboundID != "" && !inbound.IsControllerManagedTag(cfg.Tag) {
		return false, ErrTagConflict
	}
	if desiredDigest == "" {
		desiredDigest = cfg.Digest
	}
	decodedDigest, err := hex.DecodeString(desiredDigest)
	if err != nil || len(decodedDigest) != 32 {
		return false, errors.New("desired digest must be a SHA-256 hex value")
	}
	m.operations.Lock()
	defer m.operations.Unlock()

	previous, managed := m.store.Get(cfg.Tag)
	if controller.InboundID == "" {
		if (managed && previous.Controller.InboundID != "") || m.hasControllerTombstone(cfg.Tag) {
			return false, ErrControllerOwned
		}
	} else {
		if tombstone, ok := m.store.ControllerTombstone(cfg.Tag); ok {
			switch {
			case tombstone.InboundID != controller.InboundID:
				return false, ErrControllerOwnership
			case controller.DesiredRevision < tombstone.DesiredRevision:
				return false, ErrStaleRevision
			case controller.DesiredRevision == tombstone.DesiredRevision:
				return false, ErrRevisionConflict
			}
		}
		if managed && previous.Controller.InboundID != "" {
			switch {
			case previous.Controller.InboundID != controller.InboundID:
				return false, ErrControllerOwnership
			case controller.DesiredRevision < previous.Controller.DesiredRevision:
				return false, ErrStaleRevision
			case controller.DesiredRevision == previous.Controller.DesiredRevision && previous.DesiredDigest != desiredDigest:
				return false, ErrRevisionConflict
			}
		}
	}
	runtimeTags, err := m.core.ListInboundTags(ctx)
	if err != nil {
		m.setState(cfg, false, "xray runtime inventory is unavailable")
		return false, fmt.Errorf("preflight inbound %q: %w", cfg.Tag, err)
	}
	runtimeHadTag := containsTag(runtimeTags, cfg.Tag)
	if !managed && runtimeHadTag {
		return false, ErrTagConflict
	}
	if managed && previous.Config.Digest == cfg.Digest && runtimeHadTag {
		if persistErr := m.persistDesired(cfg, desiredDigest, controller); persistErr != nil {
			m.setState(cfg, false, "the desired inbound could not be persisted")
			return false, fmt.Errorf("persist inbound %q: %w", cfg.Tag, persistErr)
		}
		m.setState(cfg, true, "")
		return false, nil
	}
	if managed && previous.Config.Digest == cfg.Digest {
		err := m.core.AddInboundFromJSON(ctx, cfg.Raw)
		if err == nil || xray.IsInboundAlreadyExists(err) {
			if persistErr := m.persistDesired(cfg, desiredDigest, controller); persistErr != nil {
				m.setState(cfg, false, "the desired inbound could not be persisted")
				return false, fmt.Errorf("persist inbound %q: %w", cfg.Tag, persistErr)
			}
			m.setState(cfg, true, "")
			return true, nil
		}
		m.setState(cfg, false, "xray rejected the desired inbound")
		return false, fmt.Errorf("reconcile existing inbound %q: %w", cfg.Tag, err)
	}

	if managed {
		if err := m.core.RemoveInbound(ctx, cfg.Tag); err != nil && !xray.IsNotFound(err) {
			m.setState(previous.Config, false, "xray could not replace the inbound")
			return false, fmt.Errorf("remove previous inbound %q: %w", cfg.Tag, err)
		}
	}

	if err := m.core.AddInboundFromJSON(ctx, cfg.Raw); err != nil {
		if !xray.IsInboundAlreadyExists(err) && !runtimeHadTag {
			if after, listErr := m.core.ListInboundTags(ctx); listErr == nil && containsTag(after, cfg.Tag) {
				_ = m.core.RemoveInbound(ctx, cfg.Tag)
			}
		}
		if managed {
			_ = m.restore(ctx, previous.Config)
		} else if xray.IsInboundAlreadyExists(err) {
			return false, ErrTagConflict
		}
		m.setState(cfg, false, "xray rejected the desired inbound")
		return false, fmt.Errorf("apply inbound %q: %w", cfg.Tag, err)
	}

	if err := m.persistDesired(cfg, desiredDigest, controller); err != nil {
		_ = m.core.RemoveInbound(ctx, cfg.Tag)
		if managed {
			_ = m.restore(ctx, previous.Config)
		}
		m.setState(cfg, false, "the desired inbound could not be persisted")
		return false, fmt.Errorf("persist inbound %q: %w", cfg.Tag, err)
	}
	m.setState(cfg, true, "")
	return true, nil
}

func (m *Manager) UpdateControllerState(tag string, controller store.InboundControllerState) error {
	m.operations.Lock()
	defer m.operations.Unlock()
	if m.isProtected(tag) {
		return ErrNotManaged
	}
	return m.store.UpdateControllerState(tag, controller)
}

func (m *Manager) hasControllerTombstone(tag string) bool {
	_, ok := m.store.ControllerTombstone(tag)
	return ok
}

func containsTag(tags []string, wanted string) bool {
	for _, tag := range tags {
		if tag == wanted {
			return true
		}
	}
	return false
}

func (m *Manager) persistDesired(cfg inbound.Config, desiredDigest string, controller store.InboundControllerState) error {
	if controller.InboundID != "" {
		_, err := m.store.PutControllerDesired(cfg, desiredDigest, controller)
		return err
	}
	_, err := m.store.PutDesired(cfg, desiredDigest)
	return err
}

// Remove only deletes tags present in the dynamic store. This guard is what
// prevents DELETE or a future manifest diff from removing baseline vless-in.
func (m *Manager) Remove(ctx context.Context, tag string) error {
	m.operations.Lock()
	defer m.operations.Unlock()

	if m.isProtected(tag) {
		return ErrNotManaged
	}
	previous, managed := m.store.Get(tag)
	if !managed {
		if m.hasControllerTombstone(tag) {
			return ErrControllerOwned
		}
		return ErrNotManaged
	}
	if previous.Controller.InboundID != "" {
		return ErrControllerOwned
	}
	if err := m.core.RemoveInbound(ctx, tag); err != nil && !xray.IsNotFound(err) {
		m.setState(previous.Config, false, "xray could not remove the inbound")
		return fmt.Errorf("remove inbound %q: %w", tag, err)
	}
	if _, err := m.store.Remove(tag); err != nil {
		_ = m.restore(ctx, previous.Config)
		m.setState(previous.Config, false, "the desired inventory could not be updated")
		return fmt.Errorf("persist inbound removal %q: %w", tag, err)
	}
	m.stateMu.Lock()
	delete(m.states, tag)
	m.stateMu.Unlock()
	return nil
}

// RemoveControllerDesired is the idempotent tombstone operation used by the
// pull reconciler. It never touches protected/static tags, and a controller is
// not allowed to delete a tag owned by a different catalogue identity.
func (m *Manager) RemoveControllerDesired(ctx context.Context, tag, inboundID string, desiredRevision int64) error {
	m.operations.Lock()
	defer m.operations.Unlock()

	if m.isProtected(tag) || !inbound.IsControllerManagedTag(tag) {
		return ErrNotManaged
	}
	removeRuntime, idempotent, err := m.store.ControllerDeleteState(tag, inboundID, desiredRevision)
	if err != nil {
		return err
	}
	if idempotent {
		return nil
	}
	previous, managed := m.store.Get(tag)
	if removeRuntime {
		if !managed {
			return ErrNotManaged
		}
		if err := m.core.RemoveInbound(ctx, tag); err != nil && !xray.IsNotFound(err) {
			m.setState(previous.Config, false, "xray could not remove the inbound")
			return fmt.Errorf("remove inbound %q: %w", tag, err)
		}
	}
	if err := m.store.PutControllerTombstone(tag, inboundID, desiredRevision); err != nil {
		if removeRuntime && managed {
			_ = m.restore(ctx, previous.Config)
			m.setState(previous.Config, false, "the desired inventory could not be updated")
		}
		return fmt.Errorf("persist inbound tombstone %q: %w", tag, err)
	}
	m.stateMu.Lock()
	delete(m.states, tag)
	m.stateMu.Unlock()
	return nil
}

// Reconcile re-adds every durable dynamic inbound. Already-existing handlers are
// success. It intentionally does no deletion because the Xray API cannot safely
// distinguish a static handler from an orphaned dynamic handler.
func (m *Manager) Reconcile(ctx context.Context) (applied, failed int) {
	m.operations.Lock()
	defer m.operations.Unlock()

	for _, record := range m.store.All() {
		if m.isProtected(record.Config.Tag) {
			failed++
			m.setState(record.Config, false, "tag is protected by the static Xray configuration")
			continue
		}
		err := m.core.AddInboundFromJSON(ctx, record.Config.Raw)
		switch {
		case err == nil:
			applied++
			m.setState(record.Config, true, "")
		case xray.IsInboundAlreadyExists(err):
			applied++
			m.setState(record.Config, true, "")
		default:
			failed++
			m.setState(record.Config, false, "xray rejected the desired inbound")
		}
	}
	return applied, failed
}

func (m *Manager) Bootstrap(ctx context.Context) (applied, failed int) {
	return m.Reconcile(ctx)
}

func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.Reconcile(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (m *Manager) Inventory() []Item {
	records := m.store.All()
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	items := make([]Item, 0, len(records))
	for _, record := range records {
		item := Item{
			PublicConfig:           record.Config.Public(),
			DesiredDigest:          record.DesiredDigest,
			InboundID:              record.Controller.InboundID,
			DesiredRevision:        record.Controller.DesiredRevision,
			AppliedRevision:        record.Controller.AppliedRevision,
			ControllerStatus:       record.Controller.Status,
			AppliedClientCount:     record.Controller.AppliedClientCount,
			AppliedClientSetSHA256: record.Controller.AppliedClientSetSHA256,
			Desired:                true,
			UpdatedAt:              record.UpdatedAt,
		}
		if current, ok := m.states[record.Config.Tag]; ok && current.digest == record.Config.Digest {
			item.Applied = current.applied
			item.LastAttempt = current.lastAttempt
			item.LastError = current.lastError
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Tag < items[j].Tag })
	return items
}

// ManagedConfig is for the trusted local API adapter to retain per-node Reality
// credentials across an idempotent template apply. It must never be serialized.
func (m *Manager) ManagedConfig(tag string) (inbound.Config, bool) {
	if m.isProtected(tag) {
		return inbound.Config{}, false
	}
	record, ok := m.store.Get(tag)
	return record.Config, ok
}

// ControllerState returns a copy of the durable observed metadata without the
// private runtime config. It is used to report last-known-good revision after a
// failed replacement attempt.
func (m *Manager) ControllerState(tag string) (store.InboundControllerState, bool) {
	if m.isProtected(tag) {
		return store.InboundControllerState{}, false
	}
	record, ok := m.store.Get(tag)
	if !ok || record.Controller.InboundID == "" {
		return store.InboundControllerState{}, false
	}
	return record.Controller.Clone(), true
}

func (m *Manager) ControllerTombstone(tag string) (store.InboundControllerTombstone, bool) {
	if m.isProtected(tag) || !inbound.IsControllerManagedTag(tag) {
		return store.InboundControllerTombstone{}, false
	}
	return m.store.ControllerTombstone(tag)
}

func (m *Manager) isProtected(tag string) bool {
	_, ok := m.protected[tag]
	return ok
}

func (m *Manager) restore(ctx context.Context, cfg inbound.Config) error {
	err := m.core.AddInboundFromJSON(ctx, cfg.Raw)
	if err == nil || xray.IsInboundAlreadyExists(err) {
		m.setState(cfg, true, "")
		return nil
	}
	m.setState(cfg, false, "xray rejected the previously persisted inbound")
	return err
}

func (m *Manager) setState(cfg inbound.Config, applied bool, publicError string) {
	m.stateMu.Lock()
	m.states[cfg.Tag] = state{
		digest:      cfg.Digest,
		applied:     applied,
		lastAttempt: time.Now().UTC(),
		lastError:   publicError,
	}
	m.stateMu.Unlock()
}
