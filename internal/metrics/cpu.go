package metrics

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
)

// sampleCPU covers the same interval between collections as the network byte
// counters. Sampling one second every fifteen seconds aliases short bursts:
// it can both miss real traffic and hold an isolated peak until the next push.
// Keep steal in busy time: unavailable hypervisor time reduces real capacity.
func (c *Collector) sampleCPU(ctx context.Context) (float64, float64, error) {
	read := func() (*cpu.TimesStat, error) {
		values, err := cpu.TimesWithContext(ctx, false)
		if err != nil {
			return nil, err
		}
		if len(values) != 1 {
			return nil, fmt.Errorf("aggregate CPU counters unavailable")
		}
		return &values[0], nil
	}
	if c.previousCPU == nil {
		baseline, err := read()
		if err != nil {
			return 0, 0, err
		}
		c.previousCPU = baseline
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return 0, 0, ctx.Err()
		case <-timer.C:
		}
	}
	current, err := read()
	if err != nil {
		return 0, 0, err
	}
	previous := c.previousCPU
	c.previousCPU = current
	busy, steal := cpuIntervalPercent(*previous, *current)
	return busy, steal, nil
}

func cpuIntervalPercent(previous, current cpu.TimesStat) (float64, float64) {
	// Linux user/nice already include guest time; do not count Guest twice.
	total := func(t cpu.TimesStat) float64 {
		return t.User + t.Nice + t.System + t.Idle + t.Iowait + t.Irq + t.Softirq + t.Steal
	}
	delta := total(current) - total(previous)
	idle := current.Idle + current.Iowait - previous.Idle - previous.Iowait
	steal := current.Steal - previous.Steal
	if delta <= 0 || idle < 0 || steal < 0 {
		return 0, 0
	}
	clamp := func(v float64) float64 { return math.Max(0, math.Min(100, v)) }
	return clamp((delta - idle) / delta * 100), clamp(steal / delta * 100)
}
