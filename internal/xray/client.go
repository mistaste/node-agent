package xray

import (
	"context"
	"log"
	"time"

	handlerCmd "github.com/xtls/xray-core/app/proxyman/command"
	statsCmd "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// Client wraps the gRPC connection to the local Xray-core instance.
type Client struct {
	conn    *grpc.ClientConn
	Handler handlerCmd.HandlerServiceClient
	Stats   statsCmd.StatsServiceClient
}

func NewClient(addr string) (*Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return nil, err
	}

	c := &Client{
		conn:    conn,
		Handler: handlerCmd.NewHandlerServiceClient(conn),
		Stats:   statsCmd.NewStatsServiceClient(conn),
	}
	log.Printf("[xray] gRPC connection established to %s", addr)
	return c, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}
