package accountqos

import (
	"context"
	"testing"
	"time"
)

func TestAccountFairnessIndependentOfStreams(t *testing.T) {
	s := New(8)
	ctx := context.Background()
	now := time.Now()
	s.last = now
	s.tokens = 0
	// Account A has sixteen streams; B one. Both offer continuous demand.
	a := &account{order: 1}
	b := &account{order: 2}
	s.accounts["a"] = a
	s.accounts["b"] = b
	for i := 0; i < 160; i++ {
		a.queue = append(a.queue, &request{bytes: 1000, ctx: ctx, finish: make(chan struct{})})
	}
	for i := 0; i < 160; i++ {
		b.queue = append(b.queue, &request{bytes: 1000, ctx: ctx, finish: make(chan struct{})})
	}
	for i := 0; i < 100; i++ {
		now = now.Add(time.Millisecond)
		if _, ok := s.next(now); !ok {
			t.Fatal("grant absent")
		}
	}
	if a.granted != 50000 || b.granted != 50000 {
		t.Fatalf("unequal account allocation: %d %d", a.granted, b.granted)
	}
	// Only A demands data: it borrows the entire budget, idle B reserves nothing.
	b.queue = nil
	for i := 0; i < 20; i++ {
		now = now.Add(time.Millisecond)
		s.next(now)
	}
	if a.granted != 70000 {
		t.Fatalf("unused capacity not borrowed: %d", a.granted)
	}
}
func TestCancellationAndBoundedBurst(t *testing.T) {
	s := New(8)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.accounts["a"] = &account{queue: []*request{{bytes: 1000, ctx: ctx, finish: make(chan struct{})}}}
	if _, ok := s.next(time.Now().Add(time.Hour)); ok {
		t.Fatal("cancelled request charged")
	}
	if s.tokens > MaxGrant {
		t.Fatal("unbounded idle credit")
	}
	if s.Acquire(context.Background(), "a", MaxGrant+1) == nil {
		t.Fatal("oversized grant accepted")
	}
}
func TestGovernorHysteresis(t *testing.T) {
	g := Governor{Min: 64, Max: 400, Current: 400}
	g.Observe(99)
	g.Observe(99)
	if g.Current != 400 {
		t.Fatal("single spike reduced budget")
	}
	g.Observe(99)
	if g.Current != 340 {
		t.Fatalf("not reduced: %v", g.Current)
	}
	for i := 0; i < 6; i++ {
		g.Observe(40)
	}
	if g.Current != 357 {
		t.Fatalf("not gradually restored: %v", g.Current)
	}
	for i := 0; i < 100; i++ {
		g.Observe(100)
	}
	if g.Current != 64 {
		t.Fatal("budget floor violated")
	}
}

func TestSingleStreamRetainsFairnessAcrossGrantRoundTrips(t *testing.T) {
	s := New(100)
	ctx := context.Background()
	now := time.Now()
	s.last = now
	s.tokens = 0
	a := &account{order: 1, last: now}
	b := &account{order: 2, last: now}
	s.accounts["a"] = a
	s.accounts["b"] = b
	enqueue := func(a *account) {
		a.queue = append(a.queue, &request{bytes: 1000, ctx: ctx, finish: make(chan struct{})})
	}
	for i := 0; i < 1000; i++ {
		enqueue(a)
	}
	enqueue(b)
	nextB := 0
	for tick := 0; tick < 600; tick++ {
		if tick == nextB && len(b.queue) == 0 {
			enqueue(b)
			b.last = now
		}
		before := b.granted
		now = now.Add(80 * time.Microsecond)
		s.next(now)
		if b.granted > before {
			nextB = tick + 2
		}
	}
	difference := int64(a.granted) - int64(b.granted)
	if difference > 2000 || difference < -2000 {
		t.Fatalf("stream count advantage: A=%d B=%d", a.granted, b.granted)
	}
}

func TestBulkAccountRetainsTurnAcrossBriefReadGap(t *testing.T) {
	now := time.Now()
	ctx := context.Background()
	s := New(200)
	s.last = now
	s.tokens = MaxGrant
	enqueue := func(a *account) {
		a.queue = append(a.queue, &request{bytes: 16384, ctx: ctx, finish: make(chan struct{})})
	}
	a := &account{virtual: MaxGrant, order: 1, last: now, lastGrant: now, burstBytes: MaxGrant}
	b := &account{virtual: MaxGrant, order: 2, last: now, lastGrant: now, burstBytes: MaxGrant}
	s.accounts["a"] = a
	s.accounts["b"] = b
	for i := 0; i < 4; i++ {
		enqueue(a)
	}
	if _, ok := s.next(now); !ok {
		t.Fatal("initial turn absent")
	}
	if delay, ok := s.next(now); ok || delay <= 0 || delay > accountIdleGrace {
		t.Fatal("many streams consumed the absent single stream's turn")
	}
	enqueue(b)
	now = now.Add(500 * time.Microsecond)
	if _, ok := s.next(now); !ok || b.granted != 16384 {
		t.Fatal("returning single stream did not retain its turn")
	}
	now = now.Add(accountIdleGrace + time.Millisecond)
	if _, ok := s.next(now); !ok {
		t.Fatal("idle account kept reserving bandwidth after the bounded gap")
	}
}
func TestSmallRequestDoesNotReserveBulkShare(t *testing.T) {
	now := time.Now()
	s := New(200)
	s.last = now
	s.tokens = MaxGrant
	s.accounts["small"] = &account{virtual: 0, last: now, lastGrant: now, burstBytes: 4096}
	s.accounts["bulk"] = &account{virtual: MaxGrant, queue: []*request{{bytes: 16384, ctx: context.Background(), finish: make(chan struct{})}}}
	if _, ok := s.next(now); !ok {
		t.Fatal("a short low-demand request reserved a bulk share")
	}
}
