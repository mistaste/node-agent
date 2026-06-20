package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	handlerCmd "github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/infra/conf"
)

// AddInboundFromJSON parses a JSON inbound config (same format as config.json inbounds array
// element) and dynamically adds it to the running Xray instance without restart.
func (c *Client) AddInboundFromJSON(ctx context.Context, configJSON []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var detourConf conf.InboundDetourConfig
	if err := json.Unmarshal(configJSON, &detourConf); err != nil {
		return fmt.Errorf("parse inbound JSON: %w", err)
	}
	inboundConfig, err := detourConf.Build()
	if err != nil {
		return fmt.Errorf("build inbound config: %w", err)
	}
	_, err = c.Handler.AddInbound(ctx, &handlerCmd.AddInboundRequest{
		Inbound: inboundConfig,
	})
	return err
}

// RemoveInbound dynamically removes an inbound by tag without restart.
func (c *Client) RemoveInbound(ctx context.Context, tag string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	_, err := c.Handler.RemoveInbound(ctx, &handlerCmd.RemoveInboundRequest{
		Tag: tag,
	})
	if err != nil {
		return fmt.Errorf("remove inbound (tag=%s): %w", tag, err)
	}
	return nil
}
