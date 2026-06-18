package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreInboundsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	s := New(path)
	cfg := []byte(`{"tag":"xhttp-in","port":8443}`)
	if err := s.AddInbound("xhttp-in", cfg); err != nil {
		t.Fatal(err)
	}
	s2 := New(path)
	if err := s2.Load(); err != nil {
		t.Fatal(err)
	}
	got := s2.Inbounds()
	if len(got) != 1 || string(got[0]) != string(cfg) {
		t.Fatalf("persisted inbounds = %v", got)
	}
	_ = os.Remove(path)
}
