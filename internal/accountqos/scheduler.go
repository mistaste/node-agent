// Package accountqos implements an opt-in, node-local authenticated account budget.
package accountqos

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
)

const MaxGrant = 64 * 1024

const accountIdleGrace = 8 * time.Millisecond

type request struct {
	bytes    int
	finish   chan struct{}
	ctx      context.Context
	enqueued time.Time
}
type account struct {
	virtual    float64
	queue      []*request
	granted    uint64
	last       time.Time
	lastGrant  time.Time
	burstBytes int
	order      uint64
}
type AccountSnapshot struct {
	Pending      int     `json:"pending"`
	Virtual      float64 `json:"virtual"`
	LastAgeMs    float64 `json:"last_age_ms"`
	OldestWaitMs float64 `json:"oldest_wait_ms"`
}
type Snapshot struct {
	Accounts        map[string]AccountSnapshot `json:"accounts"`
	Virtual         float64                    `json:"virtual"`
	BudgetMbps      float64                    `json:"budget_mbps"`
	Reason          string                     `json:"budget_reason"`
	ActiveAccounts  int                        `json:"active_accounts"`
	Pending         int                        `json:"pending_requests"`
	GrantedBytes    map[string]uint64          `json:"granted_bytes"`
	UnknownRequests uint64                     `json:"unknown_requests"`
}
type Scheduler struct {
	mu       sync.Mutex
	accounts map[string]*account
	virtual  float64
	order    uint64
	rate     float64
	tokens   float64
	last     time.Time
	wake     chan struct{}
	reason   string
	unknown  uint64
}

func New(mbps float64) *Scheduler {
	return &Scheduler{accounts: make(map[string]*account), rate: mbps * 1e6 / 8, tokens: MaxGrant, last: time.Now(), wake: make(chan struct{}, 1), reason: "initial"}
}
func (s *Scheduler) refill(now time.Time) {
	s.tokens = math.Min(MaxGrant, s.tokens+math.Max(0, now.Sub(s.last).Seconds())*s.rate)
	s.last = now
}
func (s *Scheduler) SetBudget(mbps float64, reason string) {
	s.mu.Lock()
	s.refill(time.Now())
	s.rate = mbps * 1e6 / 8
	s.reason = reason
	s.mu.Unlock()
	s.signal()
}
func (s *Scheduler) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *Scheduler) Acquire(ctx context.Context, key string, n int) error {
	if n <= 0 || n > MaxGrant || key == "" {
		return errors.New("invalid grant")
	}
	r := &request{bytes: n, finish: make(chan struct{}), ctx: ctx, enqueued: time.Now()}
	s.mu.Lock()
	a := s.accounts[key]
	if a == nil {
		s.order++
		a = &account{virtual: s.virtual, order: s.order}
		s.accounts[key] = a
	}
	if len(a.queue) == 0 {
		a.virtual = math.Max(a.virtual, s.virtual-s.rate*0.25)
	}
	a.queue = append(a.queue, r)
	a.last = time.Now()
	if key == "unknown" {
		s.unknown++
	}
	s.mu.Unlock()
	s.signal()
	select {
	case <-r.finish:
		return nil
	case <-ctx.Done():
		s.signal()
		return ctx.Err()
	}
}
func (s *Scheduler) next(now time.Time) (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refill(now)
	demanding := 0
	for _, a := range s.accounts {
		if len(a.queue) > 0 {
			demanding++
		}
	}
	credit := s.rate * 0.25 / math.Max(1, float64(demanding))
	var chosen *account
	var anticipating *account
	for key, a := range s.accounts {
		for len(a.queue) > 0 && a.queue[0].ctx.Err() != nil {
			a.queue = a.queue[1:]
		}
		if len(a.queue) == 0 {
			if a.burstBytes >= MaxGrant && now.Sub(a.lastGrant) < accountIdleGrace && (anticipating == nil || a.virtual < anticipating.virtual) {
				anticipating = a
			}
			if now.Sub(a.last) > 10*time.Minute {
				delete(s.accounts, key)
			}
			continue
		}
		a.virtual = math.Max(a.virtual, s.virtual-credit)
		if chosen == nil || a.virtual < chosen.virtual || (a.virtual == chosen.virtual && a.order < chosen.order) {
			chosen = a
		}
	}
	if chosen == nil {
		return time.Hour, false
	}
	// A continuously reading single stream briefly leaves no queued grant
	// while forwarding the previous chunk. Preserve its turn across that gap;
	// otherwise many streams can consume every token before it re-enters.
	if anticipating != nil && chosen.virtual > anticipating.virtual {
		return accountIdleGrace - now.Sub(anticipating.lastGrant), false
	}
	r := chosen.queue[0]
	if s.tokens < float64(r.bytes) {
		return time.Duration((float64(r.bytes) - s.tokens) / s.rate * float64(time.Second)), false
	}
	if now.Sub(chosen.lastGrant) > 100*time.Millisecond {
		chosen.burstBytes = 0
	}
	chosen.burstBytes = min(MaxGrant, chosen.burstBytes+r.bytes)
	chosen.lastGrant = now
	chosen.virtual += float64(r.bytes)
	chosen.last = now
	chosen.queue = chosen.queue[1:]
	chosen.granted += uint64(r.bytes)
	s.tokens -= float64(r.bytes)
	s.virtual = math.Max(s.virtual, chosen.virtual-float64(r.bytes))
	close(r.finish)
	return 0, true
}
func (s *Scheduler) Run(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		delay, granted := s.next(time.Now())
		if granted {
			continue
		}
		if delay < time.Microsecond {
			delay = time.Microsecond
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(delay)
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-timer.C:
		}
	}
}
func (s *Scheduler) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Snapshot{Accounts: make(map[string]AccountSnapshot), Virtual: s.virtual, BudgetMbps: s.rate * 8 / 1e6, Reason: s.reason, GrantedBytes: make(map[string]uint64), UnknownRequests: s.unknown}
	for key, a := range s.accounts {
		oldest := float64(0)
		if len(a.queue) > 0 {
			oldest = float64(time.Since(a.queue[0].enqueued)) / float64(time.Millisecond)
		}
		out.Accounts[key] = AccountSnapshot{Pending: len(a.queue), Virtual: a.virtual, LastAgeMs: float64(time.Since(a.last)) / float64(time.Millisecond), OldestWaitMs: oldest}
		out.GrantedBytes[key] = a.granted
		out.Pending += len(a.queue)
		if time.Since(a.last) < 5*time.Second {
			out.ActiveAccounts++
		}
	}
	return out
}

type Governor struct {
	Min, Max, Current float64
	high, low         int
}

func (g *Governor) Observe(cpu float64) (float64, string) {
	if cpu >= 80 {
		g.high++
		g.low = 0
	} else if cpu <= 60 {
		g.low++
		g.high = 0
	} else {
		g.high = 0
		g.low = 0
	}
	reason := "stable"
	if g.high >= 3 {
		g.Current = math.Max(g.Min, g.Current*0.85)
		g.high = 0
		reason = "cpu_high"
	}
	if g.low >= 6 {
		g.Current = math.Min(g.Max, g.Current*1.05)
		g.low = 0
		reason = "cpu_recovered"
	}
	return g.Current, reason
}
