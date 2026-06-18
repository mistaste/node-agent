package store

import (
	"encoding/json"
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

// Store is a thread-safe, file-backed set of VLESS users.
type Store struct {
	path  string
	mu    sync.RWMutex
	users map[string]User
}

func New(path string) *Store {
	return &Store{path: path, users: make(map[string]User)}
}

// Load reads the store from disk. A missing file is treated as an empty store.
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
	var users []User
	if err := json.Unmarshal(data, &users); err != nil {
		return err
	}
	for _, u := range users {
		s.users[key(u.InboundTag, u.UUID)] = u
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

// save writes the store atomically. The caller must hold the write lock.
func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	users := make([]User, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, u)
	}
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
