package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/guardex/node-agent/internal/accountqos"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func cpu() (uint64, uint64, error) {
	b, e := os.ReadFile("/proc/stat")
	if e != nil {
		return 0, 0, e
	}
	f := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
	var total, idle uint64
	for i := 1; i < len(f) && i <= 8; i++ {
		v, e := strconv.ParseUint(f[i], 10, 64)
		if e != nil {
			return 0, 0, e
		}
		total += v
		if i == 4 || i == 5 {
			idle += v
		}
	}
	return total, idle, nil
}
func main() {
	socket := flag.String("socket", "/run/guardex-account-qos/broker.sock", "private Unix socket")
	mapping := flag.String("mapping", "/var/lib/guardex-account-qos/accounts.json", "root-owned profile bindings")
	stats := flag.String("stats", "/var/lib/guardex-account-qos/stats.json", "private aggregate counters")
	max := flag.Float64("max-mbps", 96, "maximum aggregate payload budget")
	initial := flag.Float64("initial-mbps", 96, "initial aggregate payload budget")
	min := flag.Float64("min-mbps", 32, "minimum CPU-adaptive payload budget")
	gid := flag.Int("socket-gid", 0, "additional local endpoint group allowed to request grants")
	flag.Parse()
	if *initial < *min || *initial > *max || *gid < 0 || *max < *min || *min < 1 || *max > 1000 {
		panic("invalid pilot budget")
	}
	r := &accountqos.Registry{}
	if e := r.Load(*mapping); e != nil {
		panic(e)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e := os.MkdirAll(filepath.Dir(*socket), 0700); e != nil {
		panic(e)
	}
	if _, e := os.Lstat(*socket); e == nil {
		panic("socket path already exists")
	}
	if e := os.Chown(filepath.Dir(*socket), -1, *gid); e != nil {
		panic(e)
	}
	if e := os.Chmod(filepath.Dir(*socket), 0710); e != nil {
		panic(e)
	}
	l, e := net.Listen("unix", *socket)
	if e != nil {
		panic(e)
	}
	defer os.Remove(*socket)
	if e = os.Chown(*socket, -1, *gid); e != nil {
		panic(e)
	}
	if e = os.Chmod(*socket, 0660); e != nil {
		panic(e)
	}
	s := accountqos.New(*initial)
	go s.Run(ctx)
	go func() {
		g := accountqos.Governor{Min: *min, Max: *max, Current: *initial}
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		prev, prevIdle, _ := cpu()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now, idle, e := cpu()
				if e == nil && now > prev && idle >= prevIdle && idle-prevIdle <= now-prev {
					previousBudget := g.Current
					budget, reason := g.Observe(100 * (1 - float64(idle-prevIdle)/float64(now-prev)))
					s.SetBudget(budget, reason)
					if budget != previousBudget {
						fmt.Printf("ACCOUNT_QOS_BUDGET mbps=%.2f reason=%s\n", budget, reason)
					}
				}
				prev, prevIdle = now, idle
				_ = r.Load(*mapping)
				b, _ := json.Marshal(s.Snapshot())
				temporary := *stats + ".next"
				if os.WriteFile(temporary, b, 0600) == nil {
					_ = os.Rename(temporary, *stats)
				}
			}
		}
	}()
	fmt.Println("Poland account QoS broker started; no credentials or destination addresses logged")
	if e = accountqos.Serve(ctx, l, s, r); e != nil {
		panic(e)
	}
}
