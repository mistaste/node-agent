package xray

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	handlerCmd "github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	vlessAccount "github.com/xtls/xray-core/proxy/vless"
)

// ListInboundUserIDs returns UUIDs from the private Guardex email labels used
// for VLESS users. It lets the controller reconcile runtime membership exactly
// instead of assuming the durable user store always mirrors Xray memory.
func (c *Client) ListInboundUserIDs(ctx context.Context, inboundTag string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := c.Handler.GetInboundUsers(ctx, &handlerCmd.GetInboundUserRequest{Tag: inboundTag})
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(response.Users))
	for _, user := range response.Users {
		if user == nil {
			continue
		}
		email := strings.ToLower(strings.TrimSpace(user.Email))
		if strings.HasSuffix(email, "@guardex") {
			id := strings.TrimSuffix(email, "@guardex")
			if id != "" {
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// IsAlreadyExists reports whether err indicates the user is already present in
// the inbound. Xray returns this when re-adding a user that still lives in core
// memory; the user-sync reconcile loop treats it as success, not a failure.
func IsAlreadyExists(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "already exists")
}

// IsInboundAlreadyExists matches the wording used by current and older Xray
// HandlerService releases when AddInbound is idempotently replayed.
func IsInboundAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "already exists") ||
		strings.Contains(message, "existing tag found")
}

// IsNotFound reports Xray's idempotent-delete condition. Xray versions use a
// few different phrases/codes for it, so keep this compatibility check local.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "not found") ||
		strings.Contains(message, "not exist") ||
		strings.Contains(message, "unknown handler") ||
		strings.Contains(message, "not enough information for making a decision")
}

// AddUserParams holds the parameters for adding a VLESS user to an inbound.
type AddUserParams struct {
	InboundTag string
	UUID       string
	Flow       string // "" or "xtls-rprx-vision"
	Level      uint32
}

// AddUser adds a new VLESS user to the specified inbound via Xray gRPC HandlerService.
// Zero-downtime: no config.json rewrite, no restart.
func (c *Client) AddUser(ctx context.Context, p AddUserParams) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	account := &vlessAccount.Account{
		Id:   p.UUID,
		Flow: p.Flow,
	}

	user := &protocol.User{
		Level:   p.Level,
		Email:   fmt.Sprintf("%s@guardex", p.UUID),
		Account: serial.ToTypedMessage(account),
	}

	op := serial.ToTypedMessage(&handlerCmd.AddUserOperation{User: user})

	_, err := c.Handler.AlterInbound(ctx, &handlerCmd.AlterInboundRequest{
		Tag:       p.InboundTag,
		Operation: op,
	})
	return err
}

// RemoveUser removes a VLESS user from the specified inbound by email (UUID@guardex).
func (c *Client) RemoveUser(ctx context.Context, inboundTag, uuid string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	email := fmt.Sprintf("%s@guardex", uuid)
	op := serial.ToTypedMessage(&handlerCmd.RemoveUserOperation{Email: email})

	_, err := c.Handler.AlterInbound(ctx, &handlerCmd.AlterInboundRequest{
		Tag:       inboundTag,
		Operation: op,
	})
	return err
}
