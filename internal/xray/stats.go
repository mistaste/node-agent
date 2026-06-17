package xray

import (
	"context"
	"strings"
	"time"

	statsCmd "github.com/xtls/xray-core/app/stats/command"
)

// UserTraffic holds upload/download bytes for one user.
type UserTraffic struct {
	UUID     string
	Uplink   int64
	Downlink int64
}

// QueryUserStats fetches traffic stats for a specific user from Xray StatsService.
// Xray stat names follow the pattern: "user>>>uuid@guardex>>>traffic>>>uplink"
func (c *Client) QueryUserStats(ctx context.Context, uuid string) (UserTraffic, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	prefix := "user>>>" + uuid + "@guardex>>>traffic>>>"

	resp, err := c.Stats.QueryStats(ctx, &statsCmd.QueryStatsRequest{
		Pattern: prefix,
		Reset_:  false,
	})
	if err != nil {
		return UserTraffic{}, err
	}

	var ut UserTraffic
	ut.UUID = uuid
	for _, stat := range resp.GetStat() {
		name := stat.GetName()
		switch {
		case strings.HasSuffix(name, "uplink"):
			ut.Uplink = stat.GetValue()
		case strings.HasSuffix(name, "downlink"):
			ut.Downlink = stat.GetValue()
		}
	}
	return ut, nil
}

// QueryAllUserStats fetches traffic for all users at once.
func (c *Client) QueryAllUserStats(ctx context.Context) ([]UserTraffic, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := c.Stats.QueryStats(ctx, &statsCmd.QueryStatsRequest{
		Pattern: "user>>>",
		Reset_:  false,
	})
	if err != nil {
		return nil, err
	}

	byUUID := map[string]*UserTraffic{}
	for _, stat := range resp.GetStat() {
		// name: "user>>>uuid@guardex>>>traffic>>>uplink"
		parts := strings.Split(stat.GetName(), ">>>")
		if len(parts) < 4 {
			continue
		}
		email := parts[1]
		uuid := strings.TrimSuffix(email, "@guardex")

		ut, ok := byUUID[uuid]
		if !ok {
			ut = &UserTraffic{UUID: uuid}
			byUUID[uuid] = ut
		}

		switch parts[3] {
		case "uplink":
			ut.Uplink = stat.GetValue()
		case "downlink":
			ut.Downlink = stat.GetValue()
		}
	}

	result := make([]UserTraffic, 0, len(byUUID))
	for _, ut := range byUUID {
		result = append(result, *ut)
	}
	return result, nil
}
