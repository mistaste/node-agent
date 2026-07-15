package store

import (
	"encoding/json"
	"errors"
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
	entryKey := key(u.InboundTag, u.UUID)
	previous, existed := s.users[entryKey]
	s.users[entryKey] = u
	if err := s.save(); err != nil {
		if existed {
			s.users[entryKey] = previous
		} else {
			delete(s.users, entryKey)
		}
		return err
	}
	return nil
}

// Remove deletes a user and persists the store.
func (s *Store) Remove(tag, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entryKey := key(tag, uuid)
	previous, existed := s.users[entryKey]
	delete(s.users, entryKey)
	if err := s.save(); err != nil {
		if existed {
			s.users[entryKey] = previous
		}
		return err
	}
	return nil
}

// RemoveByInboundTag atomically removes every durable user associated with a
// deleted dynamic inbound. Without this cleanup usersync could resurrect stale
// UUIDs if the same tag is later created for another catalogue revision.
func (s *Store) RemoveByInboundTag(tag string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := make(map[string]User)
	for entryKey, user := range s.users {
		if user.InboundTag == tag {
			removed[entryKey] = user
			delete(s.users, entryKey)
		}
	}
	if len(removed) == 0 {
		return nil
	}
	if err := s.save(); err != nil {
		for entryKey, user := range removed {
			s.users[entryKey] = user
		}
		return err
	}
	return nil
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

func (s *Store) UsersByInboundTag(tag string) []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0)
	for _, user := range s.users {
		if user.InboundTag == tag {
			out = append(out, user)
		}
	}
	return out
}

// save writes the store atomically. The caller must hold the write lock.
func (s *Store) save() error {
	if s.path == "" {
		return errors.New("user store path is empty")
	}
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
