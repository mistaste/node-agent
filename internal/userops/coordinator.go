// Package userops serializes native endpoint membership mutations.
// Individual stores and gRPC clients are thread-safe, but exact membership is a
// transaction spanning both systems; one shared coordinator closes that gap.
package userops

import (
	"context"
	"sync"
)

type Coordinator struct {
	once sync.Once
	gate chan struct{}
}

func New() *Coordinator      { return &Coordinator{} }
func (c *Coordinator) init() { c.once.Do(func() { c.gate = make(chan struct{}, 1) }) }

func (c *Coordinator) Lock() { _ = c.LockContext(context.Background()) }

// LockContext abandons queued work when its caller disconnects. Keep the same
// serialization across direct user mutations and manifest fetch/apply.
func (c *Coordinator) LockContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c == nil {
		return nil
	}
	c.init()
	select {
	case c.gate <- struct{}{}:
		// Cancellation and availability can become ready together.
		if err := ctx.Err(); err != nil {
			<-c.gate
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Coordinator) Unlock() {
	if c != nil {
		c.init()
		<-c.gate
	}
}
