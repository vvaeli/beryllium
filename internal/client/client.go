// Package client connects frontends (CLI, TUI) to the daemon over IPC.
package client

import (
	"context"
	"net"

	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/ipc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client holds stubs for every daemon service over one connection.
type Client struct {
	conn *grpc.ClientConn
	addr string

	Daemon        berylliumv1.DaemonServiceClient
	Subscriptions berylliumv1.SubscriptionServiceClient
	Connection    berylliumv1.ConnectionServiceClient
	Test          berylliumv1.TestServiceClient
	Settings      berylliumv1.SettingsServiceClient
	Logs          berylliumv1.LogServiceClient
	Routing       berylliumv1.RoutingServiceClient
}

// New prepares a client for the daemon at addr (socket path or pipe name).
// The connection is established lazily on the first RPC.
func New(addr string) (*Client, error) {
	conn, err := grpc.NewClient("passthrough:///beryllium",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return ipc.Dial(ctx, addr)
		}))
	if err != nil {
		return nil, err
	}
	return &Client{
		conn:          conn,
		addr:          addr,
		Daemon:        berylliumv1.NewDaemonServiceClient(conn),
		Subscriptions: berylliumv1.NewSubscriptionServiceClient(conn),
		Connection:    berylliumv1.NewConnectionServiceClient(conn),
		Test:          berylliumv1.NewTestServiceClient(conn),
		Settings:      berylliumv1.NewSettingsServiceClient(conn),
		Logs:          berylliumv1.NewLogServiceClient(conn),
		Routing:       berylliumv1.NewRoutingServiceClient(conn),
	}, nil
}

// Close releases the connection.
func (c *Client) Close() error {
	return c.conn.Close()
}
