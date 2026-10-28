package accountqos

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"regexp"
	"sync"
	"time"
)

var credentialPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var accountPattern = regexp.MustCompile(`^[0-9a-f]{32,64}$`)

type Mapping struct {
	Version     int               `json:"version"`
	Credentials map[string]string `json:"credentials"`
}
type Registry struct {
	mu      sync.RWMutex
	mapping map[string]string
}

func (r *Registry) Load(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(raw) > 4*1024*1024 {
		return errors.New("oversized account mapping")
	}
	var m Mapping
	if err = json.Unmarshal(raw, &m); err != nil {
		return err
	}
	if m.Version != 1 || len(m.Credentials) > 100000 {
		return errors.New("invalid account mapping")
	}
	for id, key := range m.Credentials {
		if !credentialPattern.MatchString(id) || !accountPattern.MatchString(key) {
			return errors.New("invalid account binding")
		}
	}
	r.mu.Lock()
	r.mapping = m.Credentials
	r.mu.Unlock()
	return nil
}
func (r *Registry) Account(id string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if key := r.mapping[id]; key != "" {
		return key
	}
	return "unknown"
}

// Frame: authenticated profile UUID (36 ASCII), direction (0/1), size (u32 BE).
func Serve(ctx context.Context, l net.Listener, s *Scheduler, r *Registry) error {
	slots := make(chan struct{}, 2048)
	go func() { <-ctx.Done(); _ = l.Close() }()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		go func() {
			defer func() { <-slots }()
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(65 * time.Second))
			var frame [41]byte
			if _, err := io.ReadFull(conn, frame[:]); err != nil {
				return
			}
			id := string(frame[:36])
			n := int(binary.BigEndian.Uint32(frame[37:]))
			if !credentialPattern.MatchString(id) || frame[36] > 1 || n <= 0 || n > MaxGrant {
				return
			}
			requestCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()
			go func() { var extra [1]byte; _, _ = conn.Read(extra[:]); cancel() }()
			if s.Acquire(requestCtx, r.Account(id), n) != nil {
				return
			}
			_, _ = conn.Write([]byte{1})
		}()
	}
}
