package store

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/guardex/node-agent/internal/inbound"
)

const inboundStoreVersion = 3

var (
	ErrControllerOwned            = errors.New("inbound tag is owned by the controller")
	ErrControllerOwnership        = errors.New("inbound tag belongs to another controller identity")
	ErrControllerStaleRevision    = errors.New("controller desired revision is stale")
	ErrControllerRevisionConflict = errors.New("controller desired state changed without a revision increment")
)

// InboundControllerState links a node-realized config to the controller's
// durable desired revision. It deliberately stores only identifiers and a hash
// of the client set; Reality private material remains inside Config.Raw.
type InboundControllerState struct {
	InboundID              string
	DesiredRevision        int64
	AppliedRevision        int64
	Status                 string
	PublicMaterialJSON     json.RawMessage
	ClientParamsJSON       json.RawMessage
	AppliedClientCount     int
	AppliedClientSetSHA256 string
}

// InboundControllerTombstone is the durable high-water mark for a deleted
// controller-owned tag. Keeping this after runtime removal is what prevents an
// old apply manifest from resurrecting the handler after a restart.
type InboundControllerTombstone struct {
	InboundID       string
	DesiredRevision int64
	UpdatedAt       time.Time
}

func (s InboundControllerState) Clone() InboundControllerState {
	s.PublicMaterialJSON = append(json.RawMessage(nil), s.PublicMaterialJSON...)
	s.ClientParamsJSON = append(json.RawMessage(nil), s.ClientParamsJSON...)
	return s
}

// InboundRecord is the durable desired state for one dynamic inbound. Config's
// Raw value contains server-side credentials and must never be serialized into
// an HTTP response; callers should use Config.Public instead.
type InboundRecord struct {
	Config        inbound.Config
	DesiredDigest string
	Controller    InboundControllerState
	UpdatedAt     time.Time
}

func (r InboundRecord) Clone() InboundRecord {
	r.Config = r.Config.Clone()
	r.Controller = r.Controller.Clone()
	return r
}

type inboundDiskStore struct {
	Version    int                              `json:"version"`
	Inbounds   []inboundDiskRecord              `json:"inbounds"`
	Tombstones []inboundControllerTombstoneDisk `json:"controller_tombstones,omitempty"`
}

type inboundControllerTombstoneDisk struct {
	Tag             string    `json:"tag"`
	InboundID       string    `json:"inbound_id"`
	DesiredRevision int64     `json:"desired_revision"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type inboundDiskRecord struct {
	Config                 json.RawMessage `json:"config"`
	DesiredDigest          string          `json:"desired_digest"`
	InboundID              string          `json:"inbound_id,omitempty"`
	DesiredRevision        int64           `json:"desired_revision,omitempty"`
	AppliedRevision        int64           `json:"applied_revision,omitempty"`
	Status                 string          `json:"status,omitempty"`
	PublicMaterialJSON     json.RawMessage `json:"public_material_json,omitempty"`
	ClientParamsJSON       json.RawMessage `json:"client_params_json,omitempty"`
	AppliedClientCount     int             `json:"applied_client_count,omitempty"`
	AppliedClientSetSHA256 string          `json:"applied_client_set_sha256,omitempty"`
	UpdatedAt              time.Time       `json:"updated_at"`
}

// InboundStore is a separate, atomic, mode-0600 desired-state inventory. It is
// intentionally independent of users.json so either store can be migrated or
// recovered without risking the other.
type InboundStore struct {
	path       string
	mu         sync.RWMutex
	records    map[string]InboundRecord
	tombstones map[string]InboundControllerTombstone
}

func NewInboundStore(path string) *InboundStore {
	return &InboundStore{
		path:       path,
		records:    make(map[string]InboundRecord),
		tombstones: make(map[string]InboundControllerTombstone),
	}
}

func (s *InboundStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var disk inboundDiskStore
	if err := json.Unmarshal(data, &disk); err != nil {
		return fmt.Errorf("decode inbound store: %w", err)
	}
	if disk.Version != 1 && disk.Version != 2 && disk.Version != inboundStoreVersion {
		return fmt.Errorf("unsupported inbound store version %d", disk.Version)
	}

	loaded := make(map[string]InboundRecord, len(disk.Inbounds))
	for i, record := range disk.Inbounds {
		cfg, err := inbound.Parse(record.Config)
		if err != nil {
			return fmt.Errorf("validate inbound store record %d: %w", i, err)
		}
		if _, exists := loaded[cfg.Tag]; exists {
			return fmt.Errorf("duplicate inbound tag %q in store", cfg.Tag)
		}
		desiredDigest := record.DesiredDigest
		if desiredDigest == "" {
			desiredDigest = cfg.Digest
		}
		decodedDigest, err := hex.DecodeString(desiredDigest)
		if err != nil || len(decodedDigest) != 32 {
			return fmt.Errorf("invalid desired digest for inbound %q", cfg.Tag)
		}
		controller := InboundControllerState{
			InboundID:              record.InboundID,
			DesiredRevision:        record.DesiredRevision,
			AppliedRevision:        record.AppliedRevision,
			Status:                 record.Status,
			PublicMaterialJSON:     append(json.RawMessage(nil), record.PublicMaterialJSON...),
			ClientParamsJSON:       append(json.RawMessage(nil), record.ClientParamsJSON...),
			AppliedClientCount:     record.AppliedClientCount,
			AppliedClientSetSHA256: record.AppliedClientSetSHA256,
		}
		if err := validateControllerState(controller); err != nil {
			return fmt.Errorf("validate controller state for inbound %q: %w", cfg.Tag, err)
		}
		if controller.InboundID != "" && !inbound.IsControllerManagedTag(cfg.Tag) {
			return fmt.Errorf("validate controller state for inbound %q: tag is outside the managed namespace", cfg.Tag)
		}
		loaded[cfg.Tag] = InboundRecord{Config: cfg, DesiredDigest: desiredDigest, Controller: controller, UpdatedAt: record.UpdatedAt.UTC()}
	}
	tombstones := make(map[string]InboundControllerTombstone, len(disk.Tombstones))
	for index, tombstone := range disk.Tombstones {
		tombstone.Tag = strings.TrimSpace(tombstone.Tag)
		tombstone.InboundID = strings.TrimSpace(tombstone.InboundID)
		if !inbound.IsControllerManagedTag(tombstone.Tag) {
			return fmt.Errorf("validate controller tombstone %d: invalid managed tag", index)
		}
		if tombstone.InboundID == "" || tombstone.DesiredRevision < 1 {
			return fmt.Errorf("validate controller tombstone %d: invalid identity or revision", index)
		}
		if _, exists := loaded[tombstone.Tag]; exists {
			return fmt.Errorf("controller tombstone %q conflicts with an active inbound", tombstone.Tag)
		}
		if _, exists := tombstones[tombstone.Tag]; exists {
			return fmt.Errorf("duplicate controller tombstone tag %q", tombstone.Tag)
		}
		tombstones[tombstone.Tag] = InboundControllerTombstone{
			InboundID:       tombstone.InboundID,
			DesiredRevision: tombstone.DesiredRevision,
			UpdatedAt:       tombstone.UpdatedAt.UTC(),
		}
	}
	s.records = loaded
	s.tombstones = tombstones
	return nil
}

// Put records one desired inbound. The boolean is false when an identical
// config is already stored, making repeated controller applies idempotent.
func (s *InboundStore) Put(cfg inbound.Config) (bool, error) {
	return s.PutDesired(cfg, cfg.Digest)
}

// PutDesired stores both the node-realized config and the digest of the source
// template. Reality keys make realized digests node-specific, while the desired
// digest remains stable and can later drive controller manifest polling.
func (s *InboundStore) PutDesired(cfg inbound.Config, desiredDigest string) (bool, error) {
	return s.putDesired(cfg, desiredDigest, InboundControllerState{})
}

// PutControllerDesired persists a controller-owned revision alongside the
// node-specific runtime config. Existing v1 records are adopted safely on the
// first successful controller apply and rewritten in the current format
// without data loss.
func (s *InboundStore) PutControllerDesired(cfg inbound.Config, desiredDigest string, controller InboundControllerState) (bool, error) {
	if controller.InboundID == "" {
		return false, errors.New("controller inbound id is required")
	}
	if err := validateControllerState(controller); err != nil {
		return false, err
	}
	return s.putDesired(cfg, desiredDigest, controller)
}

func (s *InboundStore) putDesired(cfg inbound.Config, desiredDigest string, controller InboundControllerState) (bool, error) {
	validated, err := inbound.Parse(cfg.Raw)
	if err != nil {
		return false, fmt.Errorf("validate inbound before persist: %w", err)
	}
	cfg = validated
	s.mu.Lock()
	defer s.mu.Unlock()
	if desiredDigest == "" {
		desiredDigest = cfg.Digest
	}
	decodedDigest, err := hex.DecodeString(desiredDigest)
	if err != nil || len(decodedDigest) != 32 {
		return false, errors.New("desired digest must be a SHA-256 hex value")
	}
	if controller.InboundID == "" {
		if existing, ok := s.records[cfg.Tag]; ok && existing.Controller.InboundID != "" {
			return false, ErrControllerOwned
		}
		if _, ok := s.tombstones[cfg.Tag]; ok {
			return false, ErrControllerOwned
		}
	} else {
		if !inbound.IsControllerManagedTag(cfg.Tag) {
			return false, errors.New("controller inbound tag is outside the managed namespace")
		}
		if tombstone, ok := s.tombstones[cfg.Tag]; ok {
			switch {
			case tombstone.InboundID != controller.InboundID:
				return false, ErrControllerOwnership
			case controller.DesiredRevision < tombstone.DesiredRevision:
				return false, ErrControllerStaleRevision
			case controller.DesiredRevision == tombstone.DesiredRevision:
				return false, ErrControllerRevisionConflict
			}
		}
		if existing, ok := s.records[cfg.Tag]; ok && existing.Controller.InboundID != "" {
			switch {
			case existing.Controller.InboundID != controller.InboundID:
				return false, ErrControllerOwnership
			case controller.DesiredRevision < existing.Controller.DesiredRevision:
				return false, ErrControllerStaleRevision
			case controller.DesiredRevision == existing.Controller.DesiredRevision && existing.DesiredDigest != desiredDigest:
				return false, ErrControllerRevisionConflict
			}
		}
	}
	if existing, ok := s.records[cfg.Tag]; ok && existing.Config.Digest == cfg.Digest && existing.DesiredDigest == desiredDigest && controllerStatesEqual(existing.Controller, controller) {
		return false, nil
	}
	previous, hadPrevious := s.records[cfg.Tag]
	previousTombstone, hadTombstone := s.tombstones[cfg.Tag]
	delete(s.tombstones, cfg.Tag)
	s.records[cfg.Tag] = InboundRecord{Config: cfg.Clone(), DesiredDigest: desiredDigest, Controller: controller, UpdatedAt: time.Now().UTC()}
	if err := s.saveLocked(); err != nil {
		if hadPrevious {
			s.records[cfg.Tag] = previous
		} else {
			delete(s.records, cfg.Tag)
		}
		if hadTombstone {
			s.tombstones[cfg.Tag] = previousTombstone
		}
		return false, err
	}
	return true, nil
}

func validateControllerState(controller InboundControllerState) error {
	if controller.InboundID == "" {
		if controller.DesiredRevision != 0 || controller.AppliedRevision != 0 || controller.Status != "" || len(controller.PublicMaterialJSON) != 0 || len(controller.ClientParamsJSON) != 0 || controller.AppliedClientCount != 0 || controller.AppliedClientSetSHA256 != "" {
			return errors.New("controller metadata requires an inbound id")
		}
		return nil
	}
	if strings.TrimSpace(controller.InboundID) != controller.InboundID || len(controller.InboundID) > 128 {
		return errors.New("controller inbound id is invalid")
	}
	if controller.DesiredRevision < 1 {
		return errors.New("controller desired revision must be positive")
	}
	if controller.AppliedRevision < 0 || controller.AppliedRevision > controller.DesiredRevision {
		return errors.New("controller applied revision is outside desired revision")
	}
	switch controller.Status {
	case "active", "degraded", "failed":
	default:
		return errors.New("controller status must be active, degraded, or failed")
	}
	if err := validateJSONObject("public material", controller.PublicMaterialJSON); err != nil {
		return err
	}
	if err := validateJSONObject("client params", controller.ClientParamsJSON); err != nil {
		return err
	}
	if controller.AppliedClientCount < 0 {
		return errors.New("controller client count cannot be negative")
	}
	digest, err := hex.DecodeString(controller.AppliedClientSetSHA256)
	if err != nil || len(digest) != 32 {
		return errors.New("controller client set digest must be a SHA-256 hex value")
	}
	return nil
}

func validateJSONObject(name string, raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	if len(raw) > 64*1024 || !json.Valid(raw) || bytes.TrimSpace(raw)[0] != '{' {
		return fmt.Errorf("controller %s must be a JSON object up to 64 KiB", name)
	}
	return nil
}

func controllerStatesEqual(left, right InboundControllerState) bool {
	return left.InboundID == right.InboundID &&
		left.DesiredRevision == right.DesiredRevision &&
		left.AppliedRevision == right.AppliedRevision &&
		left.Status == right.Status &&
		bytes.Equal(left.PublicMaterialJSON, right.PublicMaterialJSON) &&
		bytes.Equal(left.ClientParamsJSON, right.ClientParamsJSON) &&
		left.AppliedClientCount == right.AppliedClientCount &&
		left.AppliedClientSetSHA256 == right.AppliedClientSetSHA256
}

func (s *InboundStore) Remove(tag string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tombstones[tag]; ok {
		return false, ErrControllerOwned
	}
	previous, ok := s.records[tag]
	if !ok {
		return false, nil
	}
	if previous.Controller.InboundID != "" {
		return false, ErrControllerOwned
	}
	delete(s.records, tag)
	if err := s.saveLocked(); err != nil {
		s.records[tag] = previous
		return false, err
	}
	return true, nil
}

// ControllerDeleteState validates a tombstone before runtime mutation. The
// Manager serializes this preflight with the subsequent Xray and durable write.
// removeRuntime is true only when the exact controller-owned active record must
// be removed; an already-applied tombstone is idempotent.
func (s *InboundStore) ControllerDeleteState(tag, inboundID string, desiredRevision int64) (removeRuntime bool, idempotent bool, err error) {
	tag = strings.TrimSpace(tag)
	inboundID = strings.TrimSpace(inboundID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !inbound.IsControllerManagedTag(tag) || inboundID == "" || len(inboundID) > 128 || desiredRevision < 1 {
		return false, false, errors.New("invalid controller tombstone identity")
	}
	if tombstone, ok := s.tombstones[tag]; ok {
		switch {
		case tombstone.InboundID != inboundID:
			return false, false, ErrControllerOwnership
		case desiredRevision < tombstone.DesiredRevision:
			return false, false, ErrControllerStaleRevision
		case desiredRevision == tombstone.DesiredRevision:
			return false, true, nil
		default:
			return false, false, nil
		}
	}
	record, ok := s.records[tag]
	if !ok {
		return false, false, nil
	}
	if record.Controller.InboundID == "" || record.Controller.InboundID != inboundID {
		return false, false, ErrControllerOwnership
	}
	switch {
	case desiredRevision < record.Controller.DesiredRevision:
		return false, false, ErrControllerStaleRevision
	case desiredRevision == record.Controller.DesiredRevision:
		return false, false, ErrControllerRevisionConflict
	default:
		return true, false, nil
	}
}

// PutControllerTombstone atomically replaces an active controller record with
// its durable revision high-water mark, or advances an existing tombstone.
func (s *InboundStore) PutControllerTombstone(tag, inboundID string, desiredRevision int64) error {
	tag = strings.TrimSpace(tag)
	inboundID = strings.TrimSpace(inboundID)
	if !inbound.IsControllerManagedTag(tag) || inboundID == "" || len(inboundID) > 128 || desiredRevision < 1 {
		return errors.New("invalid controller tombstone identity")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if tombstone, ok := s.tombstones[tag]; ok {
		switch {
		case tombstone.InboundID != inboundID:
			return ErrControllerOwnership
		case desiredRevision < tombstone.DesiredRevision:
			return ErrControllerStaleRevision
		case desiredRevision == tombstone.DesiredRevision:
			return nil
		}
	}
	if record, ok := s.records[tag]; ok {
		if record.Controller.InboundID == "" || record.Controller.InboundID != inboundID {
			return ErrControllerOwnership
		}
		if desiredRevision < record.Controller.DesiredRevision {
			return ErrControllerStaleRevision
		}
		if desiredRevision == record.Controller.DesiredRevision {
			return ErrControllerRevisionConflict
		}
	}

	previousRecord, hadRecord := s.records[tag]
	previousTombstone, hadTombstone := s.tombstones[tag]
	delete(s.records, tag)
	s.tombstones[tag] = InboundControllerTombstone{
		InboundID:       inboundID,
		DesiredRevision: desiredRevision,
		UpdatedAt:       time.Now().UTC(),
	}
	if err := s.saveLocked(); err != nil {
		if hadRecord {
			s.records[tag] = previousRecord
		}
		if hadTombstone {
			s.tombstones[tag] = previousTombstone
		} else {
			delete(s.tombstones, tag)
		}
		return err
	}
	return nil
}

func (s *InboundStore) Get(tag string) (InboundRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[tag]
	return record.Clone(), ok
}

func (s *InboundStore) ControllerTombstone(tag string) (InboundControllerTombstone, bool) {
	tag = strings.TrimSpace(tag)
	s.mu.RLock()
	defer s.mu.RUnlock()
	tombstone, ok := s.tombstones[tag]
	return tombstone, ok
}

// UpdateControllerState atomically updates observed metadata without changing
// the structural Xray config. Client-only manifest changes use this path so the
// inbound handler is never recreated merely to update UUID membership.
func (s *InboundStore) UpdateControllerState(tag string, controller InboundControllerState) error {
	if err := validateControllerState(controller); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[tag]
	if !ok {
		return errors.New("managed inbound not found")
	}
	if record.Controller.InboundID != "" && record.Controller.InboundID != controller.InboundID {
		return ErrControllerOwnership
	}
	if record.Controller.InboundID == "" {
		return errors.New("managed inbound is not controller-owned")
	}
	if record.Controller.DesiredRevision != controller.DesiredRevision {
		return ErrControllerStaleRevision
	}
	previous := record
	record.Controller = controller.Clone()
	record.UpdatedAt = time.Now().UTC()
	s.records[tag] = record
	if err := s.saveLocked(); err != nil {
		s.records[tag] = previous
		return err
	}
	return nil
}

func (s *InboundStore) All() []InboundRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]InboundRecord, 0, len(s.records))
	for _, record := range s.records {
		out = append(out, record.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Config.Tag < out[j].Config.Tag })
	return out
}

// ReplaceAll atomically swaps the entire dynamic desired inventory. It is the
// persistence primitive for a future controller-manifest pull loop. Static
// config-file inbounds (including vless-in) never enter this store and therefore
// can never be removed by manifest reconciliation.
func (s *InboundStore) ReplaceAll(configs []inbound.Config) error {
	validatedConfigs := make([]inbound.Config, 0, len(configs))
	for _, cfg := range configs {
		validated, err := inbound.Parse(cfg.Raw)
		if err != nil {
			return fmt.Errorf("validate inbound before manifest persist: %w", err)
		}
		validatedConfigs = append(validatedConfigs, validated)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for tag, record := range s.records {
		if record.Controller.InboundID != "" {
			return fmt.Errorf("replace-all cannot mutate controller-owned tag %q: %w", tag, ErrControllerOwned)
		}
	}
	for _, cfg := range validatedConfigs {
		if _, owned := s.tombstones[cfg.Tag]; owned {
			return fmt.Errorf("replace-all cannot resurrect controller-owned tag %q: %w", cfg.Tag, ErrControllerOwned)
		}
	}

	now := time.Now().UTC()
	replacement := make(map[string]InboundRecord, len(validatedConfigs))
	for _, cfg := range validatedConfigs {
		if _, exists := replacement[cfg.Tag]; exists {
			return fmt.Errorf("duplicate inbound tag %q", cfg.Tag)
		}
		updatedAt := now
		if previous, ok := s.records[cfg.Tag]; ok && previous.Config.Digest == cfg.Digest {
			updatedAt = previous.UpdatedAt
		}
		controller := InboundControllerState{}
		if previous, ok := s.records[cfg.Tag]; ok && previous.Config.Digest == cfg.Digest {
			controller = previous.Controller
		}
		replacement[cfg.Tag] = InboundRecord{Config: cfg.Clone(), DesiredDigest: cfg.Digest, Controller: controller, UpdatedAt: updatedAt}
	}
	previous := s.records
	s.records = replacement
	if err := s.saveLocked(); err != nil {
		s.records = previous
		return err
	}
	return nil
}

// saveLocked writes and fsyncs a same-directory temporary file before rename,
// then fsyncs the directory. A crash therefore yields either the old complete
// inventory or the new complete inventory, never a partial JSON document.
func (s *InboundStore) saveLocked() error {
	if s.path == "" {
		return errors.New("inbound store path is empty")
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	disk := inboundDiskStore{
		Version:    inboundStoreVersion,
		Inbounds:   make([]inboundDiskRecord, 0, len(s.records)),
		Tombstones: make([]inboundControllerTombstoneDisk, 0, len(s.tombstones)),
	}
	tags := make([]string, 0, len(s.records))
	for tag := range s.records {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		record := s.records[tag]
		disk.Inbounds = append(disk.Inbounds, inboundDiskRecord{
			Config:                 append(json.RawMessage(nil), record.Config.Raw...),
			DesiredDigest:          record.DesiredDigest,
			InboundID:              record.Controller.InboundID,
			DesiredRevision:        record.Controller.DesiredRevision,
			AppliedRevision:        record.Controller.AppliedRevision,
			Status:                 record.Controller.Status,
			PublicMaterialJSON:     append(json.RawMessage(nil), record.Controller.PublicMaterialJSON...),
			ClientParamsJSON:       append(json.RawMessage(nil), record.Controller.ClientParamsJSON...),
			AppliedClientCount:     record.Controller.AppliedClientCount,
			AppliedClientSetSHA256: record.Controller.AppliedClientSetSHA256,
			UpdatedAt:              record.UpdatedAt,
		})
	}
	tombstoneTags := make([]string, 0, len(s.tombstones))
	for tag := range s.tombstones {
		tombstoneTags = append(tombstoneTags, tag)
	}
	sort.Strings(tombstoneTags)
	for _, tag := range tombstoneTags {
		tombstone := s.tombstones[tag]
		disk.Tombstones = append(disk.Tombstones, inboundControllerTombstoneDisk{
			Tag:             tag,
			InboundID:       tombstone.InboundID,
			DesiredRevision: tombstone.DesiredRevision,
			UpdatedAt:       tombstone.UpdatedAt,
		})
	}
	data, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".inbounds-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	removeTemp := true
	defer func() {
		_ = tmp.Close()
		if removeTemp {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return err
	}
	removeTemp = false

	dirHandle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirHandle.Close()
	return dirHandle.Sync()
}
