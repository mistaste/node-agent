// Package userops serializes compound Xray-user and durable-store mutations.
// Individual stores and gRPC clients are thread-safe, but exact membership is a
// transaction spanning both systems; one shared coordinator closes that gap.
package userops

import "sync"

type Coordinator struct {
	mu sync.Mutex
}

func New() *Coordinator { return &Coordinator{} }

func (c *Coordinator) Lock() {
	if c != nil {
		c.mu.Lock()
	}
}

func (c *Coordinator) Unlock() {
	if c != nil {
		c.mu.Unlock()
	}
}
