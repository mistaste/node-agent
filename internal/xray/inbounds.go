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

// InjectRealityKey mints a per-node Reality keypair for a keyless reality
// inbound and patches the config in place. Returns patched JSON + the public
// material to report to the controller. Non-reality / already-keyed inbounds
// pass through unchanged with empty public material.
func InjectRealityKey(configJSON []byte) (out []byte, publicKey, shortID string, err error) {
	var root map[string]json.RawMessage
	if err = json.Unmarshal(configJSON, &root); err != nil {
		return nil, "", "", fmt.Errorf("parse inbound: %w", err)
	}
	ssRaw, ok := root["streamSettings"]
	if !ok {
		return configJSON, "", "", nil
	}
	var ss map[string]json.RawMessage
	if err = json.Unmarshal(ssRaw, &ss); err != nil {
		return nil, "", "", fmt.Errorf("parse streamSettings: %w", err)
	}
	var security string
	_ = json.Unmarshal(ss["security"], &security)
	if security != "reality" {
		return configJSON, "", "", nil
	}
	var rs map[string]json.RawMessage
	if err = json.Unmarshal(ss["realitySettings"], &rs); err != nil {
		return nil, "", "", fmt.Errorf("parse realitySettings: %w", err)
	}
	var pk string
	_ = json.Unmarshal(rs["privateKey"], &pk)
	if pk != "" {
		return configJSON, "", "", nil // already keyed
	}
	priv, pub, kerr := GenerateRealityKeypair()
	if kerr != nil {
		return nil, "", "", kerr
	}
	sid, serr := GenerateShortID()
	if serr != nil {
		return nil, "", "", serr
	}
	rs["privateKey"], _ = json.Marshal(priv)
	rs["shortIds"], _ = json.Marshal([]string{sid})
	ss["realitySettings"], _ = json.Marshal(rs)
	root["streamSettings"], _ = json.Marshal(ss)
	out, err = json.Marshal(root)
	if err != nil {
		return nil, "", "", err
	}
	return out, pub, sid, nil
}
