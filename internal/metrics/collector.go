package metrics

import (
	"context"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/guardex/node-agent/internal/xray"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	gopsNet "github.com/shirou/gopsutil/v3/net"
)

// Snapshot holds a point-in-time view of system + xray metrics.
type Snapshot struct {
	CollectedAt                  time.Time
	CPUPercent                   float64
	MemUsedMB                    uint64
	MemTotalMB                   uint64
	MemPercent                   float64
	NetBytesSent                 uint64
	NetBytesRecv                 uint64
	NetPacketsSent               uint64
	NetPacketsRecv               uint64
	NetErrorsIn                  uint64
	NetErrorsOut                 uint64
	NetDropsIn                   uint64
	NetDropsOut                  uint64
	TCPConnections               int
	UDPConnections               int
	ConntrackCount               uint64
	ConntrackMax                 uint64
	Load1                        float64
	Load5                        float64
	Load15                       float64
	UptimeSeconds                uint64
	WireGuardHandshakeAgeSeconds int64
	Interface                    string
	LinkCapacityMbps             int
	UserTraffic                  []xray.UserTraffic
	ActiveUsers                  []ActiveUser
}

type ActiveUser struct {
	UUID     string
	Uplink   int64
	Downlink int64
	LastSeen time.Time
}

// Collector periodically gathers system and Xray metrics.
type Collector struct {
	xray     *xray.Client
	interval time.Duration

	mu     sync.RWMutex
	latest *Snapshot

	prevTraffic   map[string]int64
	lastActive    map[string]time.Time
	interfaceName string
}

func NewCollector(xrayClient *xray.Client, interval time.Duration, interfaceName ...string) *Collector {
	configuredInterface := ""
	if len(interfaceName) > 0 {
		configuredInterface = strings.TrimSpace(interfaceName[0])
	}
	return &Collector{
		xray:          xrayClient,
		interval:      interval,
		prevTraffic:   make(map[string]int64),
		lastActive:    make(map[string]time.Time),
		interfaceName: configuredInterface,
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
	if avg, err := load.Avg(); err == nil {
		snap.Load1, snap.Load5, snap.Load15 = avg.Load1, avg.Load5, avg.Load15
	}
	if uptime, err := host.Uptime(); err == nil {
		snap.UptimeSeconds = uptime
	}

	if counters, err := safeIOCounters(); err == nil {
		chosen := selectNetworkCounter(counters, c.interfaceName)
		if chosen != nil {
			snap.Interface = chosen.Name
			snap.LinkCapacityMbps = interfaceSpeedMbps(chosen.Name)
			snap.NetBytesSent = chosen.BytesSent
			snap.NetBytesRecv = chosen.BytesRecv
			snap.NetPacketsSent = chosen.PacketsSent
			snap.NetPacketsRecv = chosen.PacketsRecv
			snap.NetErrorsIn = chosen.Errin
			snap.NetErrorsOut = chosen.Errout
			snap.NetDropsIn = chosen.Dropin
			snap.NetDropsOut = chosen.Dropout
		}
	}
	if connections, err := safeConnections(); err == nil {
		for _, connection := range connections {
			switch connection.Type {
			case 1:
				if connection.Status == "ESTABLISHED" {
					snap.TCPConnections++
				}
			case 2:
				snap.UDPConnections++
			}
		}
	}
	snap.ConntrackCount = readUintFile("/proc/sys/net/netfilter/nf_conntrack_count")
	snap.ConntrackMax = readUintFile("/proc/sys/net/netfilter/nf_conntrack_max")
	snap.WireGuardHandshakeAgeSeconds = wireGuardHandshakeAge(time.Now())

	if c.xray != nil {
		if traffic, err := c.xray.QueryAllUserStats(ctx); err == nil {
			snap.UserTraffic = traffic
			snap.ActiveUsers = c.markActiveUsers(snap.CollectedAt, traffic)
		} else {
			log.Printf("[metrics] xray stats error: %v", err)
		}
	}

	c.mu.Lock()
	c.latest = snap
	c.mu.Unlock()

	log.Printf("[metrics] cpu=%.1f%% mem=%dMB/%dMB net_rx=%dMB users=%d active=%d",
		snap.CPUPercent,
		snap.MemUsedMB, snap.MemTotalMB,
		snap.NetBytesRecv/1024/1024,
		len(snap.UserTraffic),
		len(snap.ActiveUsers),
	)
}

func safeIOCounters() (counters []gopsNet.IOCountersStat, err error) {
	defer func() {
		if recover() != nil {
			counters = nil
			err = context.Canceled
		}
	}()
	return gopsNet.IOCounters(true)
}

func safeConnections() (connections []gopsNet.ConnectionStat, err error) {
	defer func() {
		if recover() != nil {
			connections = nil
			err = context.Canceled
		}
	}()
	return gopsNet.Connections("inet")
}

func selectNetworkCounter(counters []gopsNet.IOCountersStat, configured string) *gopsNet.IOCountersStat {
	if configured != "" {
		for i := range counters {
			if counters[i].Name == configured {
				return &counters[i]
			}
		}
	}
	var selected *gopsNet.IOCountersStat
	for i := range counters {
		candidate := &counters[i]
		if candidate.Name == "lo" || strings.HasPrefix(candidate.Name, "docker") || strings.HasPrefix(candidate.Name, "veth") || strings.HasPrefix(candidate.Name, "br-") {
			continue
		}
		if selected == nil || candidate.BytesRecv+candidate.BytesSent > selected.BytesRecv+selected.BytesSent {
			selected = candidate
		}
	}
	return selected
}

func interfaceSpeedMbps(interfaceName string) int {
	if interfaceName == "" || strings.ContainsAny(interfaceName, "/\\") {
		return 0
	}
	body, err := os.ReadFile("/sys/class/net/" + interfaceName + "/speed")
	if err != nil {
		return 0
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(body)))
	if err != nil || value <= 0 || value > 100000 {
		return 0
	}
	return value
}

func readUintFile(path string) uint64 {
	body, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	value, _ := strconv.ParseUint(strings.TrimSpace(string(body)), 10, 64)
	return value
}

func wireGuardHandshakeAge(now time.Time) int64 {
	body, err := exec.Command("wg", "show", "all", "latest-handshakes").Output()
	if err != nil {
		return -1
	}
	latest := int64(0)
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		value, err := strconv.ParseInt(fields[len(fields)-1], 10, 64)
		if err == nil && value > latest {
			latest = value
		}
	}
	if latest == 0 {
		return -1
	}
	age := now.Unix() - latest
	if age < 0 {
		return 0
	}
	return age
}

func (c *Collector) markActiveUsers(now time.Time, traffic []xray.UserTraffic) []ActiveUser {
	const activeWindow = 90 * time.Second

	seen := make(map[string]struct{}, len(traffic))
	byUUID := make(map[string]xray.UserTraffic, len(traffic))
	for _, user := range traffic {
		total := user.Uplink + user.Downlink
		seen[user.UUID] = struct{}{}
		byUUID[user.UUID] = user
		if prev, ok := c.prevTraffic[user.UUID]; ok && total > prev {
			c.lastActive[user.UUID] = now
		}
		c.prevTraffic[user.UUID] = total
	}

	active := make([]ActiveUser, 0, len(c.lastActive))
	for uuid, last := range c.lastActive {
		if _, ok := seen[uuid]; !ok || now.Sub(last) > activeWindow {
			delete(c.lastActive, uuid)
			continue
		}
		user := byUUID[uuid]
		active = append(active, ActiveUser{
			UUID:     uuid,
			Uplink:   user.Uplink,
			Downlink: user.Downlink,
			LastSeen: last,
		})
	}
	return active
}
