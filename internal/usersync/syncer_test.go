package usersync

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/guardex/node-agent/internal/store"
	"github.com/guardex/node-agent/internal/userops"
	"github.com/guardex/node-agent/internal/xray"
)

type blockingRuntime struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type recordingRuntime struct {
	params []xray.AddUserParams
}

func (r *recordingRuntime) AddUser(_ context.Context, params xray.AddUserParams) error {
	r.params = append(r.params, params)
	return nil
}

func (r *blockingRuntime) AddUser(context.Context, xray.AddUserParams) error {
	r.once.Do(func() { close(r.entered) })
	<-r.release
	return nil
}

func TestReconcileRestoresHysteriaProtocolAfterCoreRestart(t *testing.T) {
	users := store.New(filepath.Join(t.TempDir(), "users.json"))
	const uuid = "6f8d0c5b-6c62-4b35-9231-b2af180b5284"
	if err := users.Add(store.User{UUID: uuid, InboundTag: "gx-hysteria", Protocol: "hysteria"}); err != nil {
		t.Fatal(err)
	}
	runtime := &recordingRuntime{}
	syncer := New(runtime, users, time.Minute)
	if applied := syncer.reconcile(context.Background()); applied != 1 {
		t.Fatalf("restored users = %d", applied)
	}
	if len(runtime.params) != 1 || runtime.params[0].Protocol != "hysteria" || runtime.params[0].UUID != uuid {
		t.Fatalf("restored params = %+v", runtime.params)
	}
}

func TestReconcileHonorsSharedUserOperationCoordinator(t *testing.T) {
	users := store.New(filepath.Join(t.TempDir(), "users.json"))
	if err := users.Add(store.User{
		UUID:       "6f8d0c5b-6c62-4b35-9231-b2af180b5284",
		InboundTag: "gx-usersync-lock",
	}); err != nil {
		t.Fatal(err)
	}

	coordinator := userops.New()
	coordinator.Lock()
	runtime := &blockingRuntime{entered: make(chan struct{}), release: make(chan struct{})}
	syncer := New(runtime, users, time.Minute, coordinator)
	done := make(chan struct{})
	go func() {
		defer close(done)
		syncer.reconcile(context.Background())
	}()

	select {
	case <-runtime.entered:
		t.Fatal("usersync reached Xray while the shared user-operation lock was held")
	case <-time.After(50 * time.Millisecond):
	}
	coordinator.Unlock()

	select {
	case <-runtime.entered:
	case <-time.After(time.Second):
		t.Fatal("usersync did not resume after the shared lock was released")
	}
	close(runtime.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("usersync did not finish after the runtime operation completed")
	}
}
