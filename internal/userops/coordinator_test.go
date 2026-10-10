package userops

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLockContextCancellationAndReuse(t *testing.T) {
	var c Coordinator // zero value also works for existing callers
	c.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := c.LockContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
	c.Unlock()
	if err := c.LockContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Unlock()
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if err := c.LockContext(ctx2); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	c.Lock()
	c.Unlock()
}

func TestLockContextResumesAfterRelease(t *testing.T) {
	c := New()
	c.Lock()
	done := make(chan error, 1)
	go func() {
		err := c.LockContext(context.Background())
		done <- err
		if err == nil {
			c.Unlock()
		}
	}()
	select {
	case <-done:
		t.Fatal("entered a held coordinator")
	case <-time.After(10 * time.Millisecond):
	}
	c.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter did not resume")
	}
}
