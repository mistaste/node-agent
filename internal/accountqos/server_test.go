package accountqos

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRegistryRetainsBindingAfterInvalidReload(t *testing.T) {
	p := filepath.Join(t.TempDir(), "map.json")
	id := "11111111-1111-1111-1111-111111111111"
	key := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	b, _ := json.Marshal(Mapping{Version: 1, Credentials: map[string]string{id: key}})
	os.WriteFile(p, b, 0600)
	r := &Registry{}
	if e := r.Load(p); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(p, []byte(`{}`), 0600)
	if r.Load(p) == nil {
		t.Fatal("invalid mapping accepted")
	}
	if r.Account(id) != key || r.Account("missing") != "unknown" {
		t.Fatal("binding lost")
	}
}
func TestBrokerCombinesCredentialsAndDirections(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "gxq-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "broker.sock")
	l, e := net.Listen("unix", path)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(8)
	r := &Registry{mapping: map[string]string{"11111111-1111-1111-1111-111111111111": "account", "22222222-2222-2222-2222-222222222222": "account"}}
	go s.Run(ctx)
	go Serve(ctx, l, s, r)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, e := net.Dial("unix", path)
			if e != nil {
				t.Error(e)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			var f [41]byte
			id := "11111111-1111-1111-1111-111111111111"
			if i == 1 {
				id = "22222222-2222-2222-2222-222222222222"
			}
			copy(f[:36], id)
			f[36] = byte(i)
			binary.BigEndian.PutUint32(f[37:], 1000)
			c.Write(f[:])
			var reply [1]byte
			if _, e = io.ReadFull(c, reply[:]); e != nil || reply[0] != 1 {
				t.Errorf("grant: %v", e)
			}
		}(i)
	}
	wg.Wait()
	snapshot := s.Snapshot()
	if len(snapshot.GrantedBytes) != 1 || snapshot.GrantedBytes["account"] != 2000 {
		t.Fatalf("profile/direction split: %+v", snapshot)
	}
}
