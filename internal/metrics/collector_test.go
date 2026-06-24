package metrics

import (
	"testing"
	"time"

	"github.com/guardex/node-agent/internal/xray"
)

func TestMarkActiveUsersCountsOnlyRecentTrafficGrowth(t *testing.T) {
	c := NewCollector(nil, 15*time.Second)
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)

	if got := c.markActiveUsers(now, []xray.UserTraffic{{UUID: "u1", Uplink: 100, Downlink: 0}}); got != 0 {
		t.Fatalf("first cumulative sample active users = %d, want 0", got)
	}
	if got := c.markActiveUsers(now.Add(15*time.Second), []xray.UserTraffic{{UUID: "u1", Uplink: 120, Downlink: 0}}); got != 1 {
		t.Fatalf("traffic growth active users = %d, want 1", got)
	}
	if got := c.markActiveUsers(now.Add(60*time.Second), []xray.UserTraffic{{UUID: "u1", Uplink: 120, Downlink: 0}}); got != 1 {
		t.Fatalf("recent idle active users = %d, want 1", got)
	}
	if got := c.markActiveUsers(now.Add(120*time.Second), []xray.UserTraffic{{UUID: "u1", Uplink: 120, Downlink: 0}}); got != 0 {
		t.Fatalf("stale idle active users = %d, want 0", got)
	}
}
