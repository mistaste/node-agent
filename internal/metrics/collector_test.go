package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/guardex/node-agent/internal/xray"
)

func TestCollectWithoutXrayReportsHostMetrics(t *testing.T) {
	c := NewCollector(nil, 15*time.Second)
	c.collect(context.Background())

	snapshot := c.Latest()
	if snapshot == nil {
		t.Fatal("metrics-only collection produced no snapshot")
	}
	if snapshot.CollectedAt.IsZero() {
		t.Fatal("metrics-only snapshot has no collection time")
	}
	if snapshot.MemTotalMB == 0 {
		t.Fatal("metrics-only snapshot has no host memory total")
	}
	if len(snapshot.UserTraffic) != 0 || len(snapshot.ActiveUsers) != 0 {
		t.Fatalf("metrics-only snapshot contains Xray users: %+v", snapshot)
	}
}

func TestMarkActiveUsersCountsOnlyRecentTrafficGrowth(t *testing.T) {
	c := NewCollector(nil, 15*time.Second)
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)

	if got := c.markActiveUsers(now, []xray.UserTraffic{{UUID: "u1", Uplink: 100, Downlink: 0}}); len(got) != 0 {
		t.Fatalf("first cumulative sample active users = %d, want 0", len(got))
	}
	if got := c.markActiveUsers(now.Add(15*time.Second), []xray.UserTraffic{{UUID: "u1", Uplink: 120, Downlink: 0}}); len(got) != 1 || got[0].UUID != "u1" {
		t.Fatalf("traffic growth active users = %+v, want u1", got)
	}
	if got := c.markActiveUsers(now.Add(60*time.Second), []xray.UserTraffic{{UUID: "u1", Uplink: 120, Downlink: 0}}); len(got) != 1 {
		t.Fatalf("recent idle active users = %d, want 1", len(got))
	}
	if got := c.markActiveUsers(now.Add(120*time.Second), []xray.UserTraffic{{UUID: "u1", Uplink: 120, Downlink: 0}}); len(got) != 0 {
		t.Fatalf("stale idle active users = %d, want 0", len(got))
	}
}
