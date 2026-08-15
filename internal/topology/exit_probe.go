package topology

import (
	"context"
	"net"
	"sync"
	"time"
)

// probeExits performs bounded TCP-connect measurements only against the
// controller-provided exit node-agent endpoints. It sends no application data
// and returns no client or destination information.
func probeExits(ctx context.Context, targets []ExitProbe) []ExitProbeResult {
	if len(targets) == 0 {
		return nil
	}
	results := make(chan ExitProbeResult, len(targets))
	var group sync.WaitGroup
	for _, target := range targets {
		target := target
		group.Add(1)
		go func() {
			defer group.Done()
			probeCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			defer cancel()
			started := time.Now()
			conn, err := (&net.Dialer{}).DialContext(probeCtx, "tcp4", target.Endpoint.String())
			if err != nil {
				return
			}
			_ = conn.Close()
			elapsed := int(time.Since(started).Milliseconds())
			if elapsed < 1 {
				elapsed = 1
			}
			if elapsed <= 10000 {
				results <- ExitProbeResult{ExitServerID: target.ExitServerID, TCPRTTMs: elapsed}
			}
		}()
	}
	group.Wait()
	close(results)
	out := make([]ExitProbeResult, 0, len(results))
	for result := range results {
		out = append(out, result)
	}
	return out
}
