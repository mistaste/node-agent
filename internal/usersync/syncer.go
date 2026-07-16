package usersync

import (
	"context"
	"log"
	"time"

	"github.com/guardex/node-agent/internal/store"
	"github.com/guardex/node-agent/internal/userops"
	"github.com/guardex/node-agent/internal/xray"
)

// Syncer keeps Xray's in-memory user set aligned with the persistent store.
// Xray holds managed VLESS/Hysteria users only in memory, so any Xray restart (upgrade, crash,
// reboot) drops every user and breaks all active profiles. The Syncer re-applies
// the stored users on startup and on a periodic reconcile loop, so users are
// restored automatically within one interval of an Xray restart.
type Syncer struct {
	xray     userRuntime
	store    *store.Store
	interval time.Duration
	userOps  *userops.Coordinator
}

type userRuntime interface {
	AddUser(context.Context, xray.AddUserParams) error
}

func New(xrayClient userRuntime, st *store.Store, interval time.Duration, coordinators ...*userops.Coordinator) *Syncer {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	coordinator := userops.New()
	if len(coordinators) > 0 && coordinators[0] != nil {
		coordinator = coordinators[0]
	}
	return &Syncer{xray: xrayClient, store: st, interval: interval, userOps: coordinator}
}

// reconcile re-adds every stored user to Xray. Users already present in core are
// skipped, so the call is idempotent and cheap on a steady-state node. Returns
// the number of users that were actually (re)applied.
func (s *Syncer) reconcile(ctx context.Context) int {
	s.userOps.Lock()
	defer s.userOps.Unlock()
	applied := 0
	for _, u := range s.store.All() {
		err := s.xray.AddUser(ctx, xray.AddUserParams{
			InboundTag: u.InboundTag,
			UUID:       u.UUID,
			Protocol:   u.Protocol,
			Flow:       u.Flow,
			Level:      u.Level,
		})
		switch {
		case err == nil:
			applied++
		case xray.IsAlreadyExists(err):
			// already in core — nothing to do
		default:
			log.Printf("[usersync] durable user re-apply failed")
		}
	}
	return applied
}

// Bootstrap applies all stored users once at startup.
func (s *Syncer) Bootstrap(ctx context.Context) {
	n := s.reconcile(ctx)
	log.Printf("[usersync] bootstrap: %d user(s) applied from store", n)
}

// Run reconciles the store into Xray every interval until ctx is cancelled.
// When Xray restarts and loses its users, the next tick restores them.
func (s *Syncer) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	log.Printf("[usersync] reconcile loop started, interval %s", s.interval)
	for {
		select {
		case <-ticker.C:
			if n := s.reconcile(ctx); n > 0 {
				log.Printf("[usersync] reconcile: restored %d user(s) to Xray", n)
			}
		case <-ctx.Done():
			return
		}
	}
}
