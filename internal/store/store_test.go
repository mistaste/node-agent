package store

import (
	"path/filepath"
	"testing"
)

func TestRemoveByInboundTagIsDurableAndScoped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	users := New(path)
	for _, user := range []User{
		{UUID: "one", InboundTag: "dynamic-a"},
		{UUID: "two", InboundTag: "dynamic-a"},
		{UUID: "legacy", InboundTag: "vless-in"},
	} {
		if err := users.Add(user); err != nil {
			t.Fatal(err)
		}
	}
	if err := users.RemoveByInboundTag("dynamic-a"); err != nil {
		t.Fatal(err)
	}
	if got := users.UsersByInboundTag("dynamic-a"); len(got) != 0 {
		t.Fatalf("dynamic users remained: %+v", got)
	}
	if got := users.UsersByInboundTag("vless-in"); len(got) != 1 || got[0].UUID != "legacy" {
		t.Fatalf("other inbound users changed: %+v", got)
	}
	reloaded := New(path)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	if len(reloaded.UsersByInboundTag("dynamic-a")) != 0 || len(reloaded.UsersByInboundTag("vless-in")) != 1 {
		t.Fatalf("durable scoped removal failed: %+v", reloaded.All())
	}
}

func TestRemoveByInboundTagRollsBackMemoryWhenPersistenceFails(t *testing.T) {
	users := New("")
	users.users[key("dynamic", "one")] = User{UUID: "one", InboundTag: "dynamic"}
	if err := users.RemoveByInboundTag("dynamic"); err == nil {
		t.Fatal("broken durable store unexpectedly succeeded")
	}
	if got := users.UsersByInboundTag("dynamic"); len(got) != 1 {
		t.Fatalf("memory was not rolled back: %+v", got)
	}
}
