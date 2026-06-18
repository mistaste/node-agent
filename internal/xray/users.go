package xray

import (
	"context"
	"fmt"
	"strings"
	"time"

	handlerCmd "github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	vlessAccount "github.com/xtls/xray-core/proxy/vless"
)

// IsAlreadyExists reports whether err indicates the user is already present in
// the inbound. Xray returns this when re-adding a user that still lives in core
// memory; the user-sync reconcile loop treats it as success, not a failure.
func IsAlreadyExists(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "already exists")
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
