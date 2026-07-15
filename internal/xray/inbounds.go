package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	handlerCmd "github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// ListInboundTags returns the runtime handler inventory used by the manager's
// ownership preflight. This prevents a failed AddInbound cleanup from ever
// deleting a tag that existed before the managed operation.
func (c *Client) ListInboundTags(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := c.Handler.ListInbounds(ctx, &handlerCmd.ListInboundsRequest{IsOnlyTags: true})
	if err != nil {
		return nil, fmt.Errorf("list inbound tags: %w", err)
	}
	tags := make([]string, 0, len(response.Inbounds))
	for _, item := range response.Inbounds {
		if item != nil && item.Tag != "" {
			tags = append(tags, item.Tag)
		}
	}
	sort.Strings(tags)
	return tags, nil
}

// AddInboundFromJSON parses a JSON inbound config (same format as config.json inbounds array
// element) and dynamically adds it to the running Xray instance without restart.
func (c *Client) AddInboundFromJSON(ctx context.Context, configJSON []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	inboundConfig, err := buildInboundFromJSON(configJSON)
	if err != nil {
		return err
	}
	_, err = c.Handler.AddInbound(ctx, &handlerCmd.AddInboundRequest{
		Inbound: inboundConfig,
	})
	return err
}

func buildInboundFromJSON(configJSON []byte) (*core.InboundHandlerConfig, error) {
	var detourConf conf.InboundDetourConfig
	if err := json.Unmarshal(configJSON, &detourConf); err != nil {
		return nil, fmt.Errorf("parse inbound JSON: %w", err)
	}
	inboundConfig, err := detourConf.Build()
	if err != nil {
		return nil, fmt.Errorf("build inbound config: %w", err)
	}
	return inboundConfig, nil
}

// ValidateInboundForCore exercises the exact xray-core config builder linked
// into the agent without mutating runtime state.
func ValidateInboundForCore(configJSON []byte) error {
	_, err := buildInboundFromJSON(configJSON)
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

// InjectRealityKey mints per-node server key material when a desired Reality
// template intentionally omits it. The private key remains in the returned
// node-side config; only publicKey and shortID are safe API response values.
func InjectRealityKey(configJSON []byte) (out []byte, publicKey, shortID string, err error) {
	return EnsureRealityKey(configJSON, nil)
}

// EnsureRealityKey prepares a Reality template. If it is keyless and the same
// tag is already managed, previousConfig supplies that node's existing key so a
// retried POST or a non-key-related edit does not rotate credentials.
func EnsureRealityKey(configJSON, previousConfig []byte) (out []byte, publicKey, shortID string, err error) {
	var root map[string]json.RawMessage
	if err = json.Unmarshal(configJSON, &root); err != nil {
		return nil, "", "", fmt.Errorf("parse inbound: %w", err)
	}
	var stream map[string]json.RawMessage
	if err = json.Unmarshal(root["streamSettings"], &stream); err != nil {
		return nil, "", "", fmt.Errorf("parse streamSettings: %w", err)
	}
	var security string
	if err = json.Unmarshal(stream["security"], &security); err != nil {
		return nil, "", "", fmt.Errorf("parse stream security: %w", err)
	}
	if security != "reality" {
		return append([]byte(nil), configJSON...), "", "", nil
	}
	var reality map[string]json.RawMessage
	if err = json.Unmarshal(stream["realitySettings"], &reality); err != nil {
		return nil, "", "", fmt.Errorf("parse realitySettings: %w", err)
	}
	var privateKey string
	_ = json.Unmarshal(reality["privateKey"], &privateKey)
	var shortIDs []string
	_ = json.Unmarshal(reality["shortIds"], &shortIDs)

	if privateKey == "" && len(previousConfig) > 0 {
		previousPrivateKey, previousShortID := realityCredentials(previousConfig)
		privateKey = previousPrivateKey
		if len(shortIDs) == 0 {
			shortID = previousShortID
		}
	}
	if privateKey == "" {
		privateKey, publicKey, err = GenerateRealityKeypair()
		if err != nil {
			return nil, "", "", err
		}
	} else {
		publicKey, err = RealityPublicKey(privateKey)
		if err != nil {
			return nil, "", "", err
		}
	}
	if shortID == "" && len(shortIDs) > 0 {
		shortID = shortIDs[0]
	}
	if shortID == "" {
		shortID, err = GenerateShortID()
		if err != nil {
			return nil, "", "", err
		}
	}
	reality["privateKey"], _ = json.Marshal(privateKey)
	reality["shortIds"], _ = json.Marshal([]string{shortID})
	stream["realitySettings"], _ = json.Marshal(reality)
	root["streamSettings"], _ = json.Marshal(stream)
	out, err = json.Marshal(root)
	if err != nil {
		return nil, "", "", fmt.Errorf("marshal keyed inbound: %w", err)
	}
	return out, publicKey, shortID, nil
}

func realityCredentials(configJSON []byte) (privateKey, shortID string) {
	var root struct {
		StreamSettings struct {
			Security        string `json:"security"`
			RealitySettings struct {
				PrivateKey string   `json:"privateKey"`
				ShortIDs   []string `json:"shortIds"`
			} `json:"realitySettings"`
		} `json:"streamSettings"`
	}
	if json.Unmarshal(configJSON, &root) != nil || root.StreamSettings.Security != "reality" {
		return "", ""
	}
	if len(root.StreamSettings.RealitySettings.ShortIDs) > 0 {
		shortID = root.StreamSettings.RealitySettings.ShortIDs[0]
	}
	return root.StreamSettings.RealitySettings.PrivateKey, shortID
}
