package metrics

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/guardex/node-agent/internal/xray"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	gopsNet "github.com/shirou/gopsutil/v3/net"
)

// Snapshot holds a point-in-time view of system + xray metrics.
type Snapshot struct {
	CollectedAt  time.Time
	CPUPercent   float64
	MemUsedMB    uint64
	MemTotalMB   uint64
	MemPercent   float64
	NetBytesSent uint64
	NetBytesRecv uint64
	UserTraffic  []xray.UserTraffic
}

// Collector periodically gathers system and Xray metrics.
type Collector struct {
	xray     *xray.Client
	interval time.Duration

	mu     sync.RWMutex
	latest *Snapshot
}

func NewCollector(xrayClient *xray.Client, interval time.Duration) *Collector {
	return &Collector{
		xray:     xrayClient,
		interval: interval,
	}
}

// Latest returns the most recent snapshot (nil before the first collection).
func (c *Collector) Latest() *Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.latest
}

// Run starts the periodic collection loop. Blocks until ctx is cancelled.
func (c *Collector) Run(ctx context.Context) {
	log.Printf("[metrics] collector started, interval=%s", c.interval)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	c.collect(ctx)

	for {
		select {
		case <-ticker.C:
			c.collect(ctx)
		case <-ctx.Done():
			log.Println("[metrics] collector stopped")
			return
		}
	}
}

func (c *Collector) collect(ctx context.Context) {
	snap := &Snapshot{CollectedAt: time.Now()}

	if percents, err := cpu.Percent(time.Second, false); err == nil && len(percents) > 0 {
		snap.CPUPercent = percents[0]
	}

	if vm, err := mem.VirtualMemory(); err == nil {
		snap.MemUsedMB = vm.Used / 1024 / 1024
		snap.MemTotalMB = vm.Total / 1024 / 1024
		snap.MemPercent = vm.UsedPercent
	}

	if counters, err := gopsNet.IOCounters(false); err == nil && len(counters) > 0 {
		snap.NetBytesSent = counters[0].BytesSent
		snap.NetBytesRecv = counters[0].BytesRecv
	}

	if traffic, err := c.xray.QueryAllUserStats(ctx); err == nil {
		snap.UserTraffic = traffic
	} else {
		log.Printf("[metrics] xray stats error: %v", err)
	}

	c.mu.Lock()
	c.latest = snap
	c.mu.Unlock()

	log.Printf("[metrics] cpu=%.1f%% mem=%dMB/%dMB net_rx=%dMB users=%d",
		snap.CPUPercent,
		snap.MemUsedMB, snap.MemTotalMB,
		snap.NetBytesRecv/1024/1024,
		len(snap.UserTraffic),
	)
}
