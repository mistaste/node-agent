package metrics

import (
	"math"
	"testing"

	"github.com/shirou/gopsutil/v3/cpu"
)

func TestCPUIntervalIncludesTrafficBetweenCollectionInstants(t *testing.T) {
	// Two cores: a three-second burst consumes 4.8 of 30 CPU seconds.
	// A one-second sample could report either 0% or 80%; the full interval is 16%.
	busy, _ := cpuIntervalPercent(cpu.TimesStat{}, cpu.TimesStat{User: 4.8, Idle: 25.2})
	if math.Abs(busy-16) > 0.001 {
		t.Fatalf("busy=%v, want 16", busy)
	}
}

func TestCPUIntervalPreservesSaturationAndHypervisorContention(t *testing.T) {
	for _, tc := range []struct {
		name        string
		now         cpu.TimesStat
		busy, steal float64
	}{
		{"saturated", cpu.TimesStat{User: 25, System: 5}, 100, 0},
		{"steal", cpu.TimesStat{User: 3, Steal: 6, Idle: 21}, 30, 20},
		{"guest", cpu.TimesStat{User: 15, Guest: 10, Idle: 15}, 50, 0},
		{"iowait", cpu.TimesStat{User: 3, Iowait: 6, Idle: 21}, 10, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			busy, steal := cpuIntervalPercent(cpu.TimesStat{}, tc.now)
			if math.Abs(busy-tc.busy) > 0.001 || math.Abs(steal-tc.steal) > 0.001 {
				t.Fatalf("got %v/%v, want %v/%v", busy, steal, tc.busy, tc.steal)
			}
		})
	}
}

func TestCPUIntervalHandlesCounterReset(t *testing.T) {
	busy, steal := cpuIntervalPercent(cpu.TimesStat{User: 10, Idle: 50}, cpu.TimesStat{User: 1, Idle: 2})
	if busy != 0 || steal != 0 {
		t.Fatalf("counter reset produced %v/%v", busy, steal)
	}
}
