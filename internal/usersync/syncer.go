package usersync

import (
	"context"
	"log"
	"time"

	"github.com/guardex/node-agent/internal/store"
	"github.com/guardex/node-agent/internal/xray"
)

// Syncer keeps Xray's in-memory user set aligned with the persistent store.
// Xray holds VLESS users only in memory, so any Xray restart (upgrade, crash,
// reboot) drops every user and breaks all active profiles. The Syncer re-applies
// the stored users on startup and on a periodic reconcile loop, so users are
// restored automatically within one interval of an Xray restart.
type Syncer struct {
	xray     *xray.Client
	store    *store.Store
	interval time.Duration
}

func New(xrayClient *xray.Client, st *store.Store, interval time.Duration) *Syncer {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Syncer{xray: xrayClient, store: st, interval: interval}
}

// reapplyInbounds re-adds every stored dynamic inbound to Xray. Inbounds already
// present are silently skipped. This must run before reapplying users so that the
// inbound tags exist when users are added.
func (s *Syncer) reapplyInbounds(ctx context.Context) int {
	applied := 0
	for _, cfg := range s.store.Inbounds() {
		err := s.xray.AddInboundFromJSON(ctx, cfg)
		switch {
		case err == nil:
			applied++
		case xray.IsAlreadyExists(err):
			// already in core — nothing to do
		default:
			log.Printf("[usersync] re-add inbound: %v", err)
		}
	}
	return applied
}

// reconcile re-adds every stored user to Xray. Users already present in core are
// skipped, so the call is idempotent and cheap on a steady-state node. Returns
// the number of users that were actually (re)applied.
func (s *Syncer) reconcile(ctx context.Context) int {
	applied := 0
	for _, u := range s.store.All() {
		err := s.xray.AddUser(ctx, xray.AddUserParams{
			InboundTag: u.InboundTag,
			UUID:       u.UUID,
			Flow:       u.Flow,
			Level:      u.Level,
		})
		switch {
		case err == nil:
			applied++
		case xray.IsAlreadyExists(err):
			// already in core — nothing to do
		default:
			log.Printf("[usersync] re-add %s: %v", u.UUID, err)
		}
	}
	return applied
}

// Bootstrap applies all stored inbounds and users once at startup.
// Inbounds are restored first so that user AddUser calls find their target tags.
func (s *Syncer) Bootstrap(ctx context.Context) {
	ni := s.reapplyInbounds(ctx)
	if ni > 0 {
		log.Printf("[usersync] bootstrap: %d inbound(s) applied from store", ni)
	}
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
