package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// User is a VLESS user persisted to disk so it can be re-applied to Xray after
// a restart. Xray keeps users only in memory, so the store is the durable record.
type User struct {
	UUID       string `json:"uuid"`
	InboundTag string `json:"inbound_tag"`
	Flow       string `json:"flow"`
	Level      uint32 `json:"level"`
}

func key(tag, uuid string) string { return tag + "|" + uuid }

// diskStore is the on-disk representation. It supports both legacy ([]User array)
// and the current envelope format that also holds dynamic inbounds.
type diskStore struct {
	Users    []User                     `json:"users"`
	Inbounds map[string]json.RawMessage `json:"inbounds,omitempty"`
}

// Store is a thread-safe, file-backed set of VLESS users and dynamic inbounds.
type Store struct {
	path     string
	mu       sync.RWMutex
	users    map[string]User
	inbounds map[string]json.RawMessage
}

func New(path string) *Store {
	return &Store{
		path:     path,
		users:    make(map[string]User),
		inbounds: make(map[string]json.RawMessage),
	}
}

// Load reads the store from disk. A missing file is treated as an empty store.
// Handles the legacy format (bare []User array) for backward compatibility.
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	// Try new envelope format first.
	var ds diskStore
	if err := json.Unmarshal(data, &ds); err != nil {
		return err
	}

	// Legacy format: a bare JSON array decodes into diskStore with Users populated
	// only if it happened to be an object. Detect legacy by checking if the raw
	// bytes start with '['.
	trimmed := data
	for len(trimmed) > 0 && (trimmed[0] == ' ' || trimmed[0] == '\t' || trimmed[0] == '\n' || trimmed[0] == '\r') {
		trimmed = trimmed[1:]
	}
	if len(trimmed) > 0 && trimmed[0] == '[' {
		// Legacy: bare []User array.
		var users []User
		if err := json.Unmarshal(data, &users); err != nil {
			return err
		}
		for _, u := range users {
			s.users[key(u.InboundTag, u.UUID)] = u
		}
		return nil
	}

	for _, u := range ds.Users {
		s.users[key(u.InboundTag, u.UUID)] = u
	}
	for tag, cfg := range ds.Inbounds {
		// Compact on load so in-memory form is always whitespace-free,
		// matching what AddInbound stores.
		compacted, err := compactJSON(cfg)
		if err != nil {
			return fmt.Errorf("compact inbound %q on load: %w", tag, err)
		}
		s.inbounds[tag] = json.RawMessage(compacted)
	}
	return nil
}

// Add records a user and persists the store.
func (s *Store) Add(u User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[key(u.InboundTag, u.UUID)] = u
	return s.save()
}

// Remove deletes a user and persists the store.
func (s *Store) Remove(tag, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, key(tag, uuid))
	return s.save()
}

// All returns a snapshot of every stored user.
func (s *Store) All() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	return out
}

// AddInbound records a dynamic inbound config (with its minted key) and persists.
// The config is stored in compacted form so round-trip comparisons are stable.
func (s *Store) AddInbound(tag string, cfg []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	compact, err := compactJSON(cfg)
	if err != nil {
		return fmt.Errorf("store inbound %q: %w", tag, err)
	}
	s.inbounds[tag] = json.RawMessage(compact)
	return s.save()
}

// RemoveInbound deletes a persisted inbound and persists the store.
func (s *Store) RemoveInbound(tag string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inbounds, tag)
	return s.save()
}

// Inbounds returns a snapshot of every stored inbound config (one []byte per inbound).
func (s *Store) Inbounds() [][]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([][]byte, 0, len(s.inbounds))
	for _, cfg := range s.inbounds {
		out = append(out, []byte(cfg))
	}
	return out
}

// compactJSON returns the JSON-compacted form of b (removes insignificant whitespace).
func compactJSON(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// save writes the store atomically. The caller must hold the write lock.
func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	users := make([]User, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, u)
	}
	ds := diskStore{
		Users:    users,
		Inbounds: s.inbounds,
	}
	data, err := json.MarshalIndent(ds, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
