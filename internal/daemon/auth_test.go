package daemon

import (
	"context"
	"net"
	"testing"

	"github.com/vvaeli/beryllium/internal/ipc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestAuthUnary(t *testing.T) {
	handler := func(context.Context, any) (any, error) { return "ok", nil }
	addr := &net.UnixAddr{Name: "x", Net: "unix"}
	tests := []struct {
		name string
		ctx  context.Context
		want codes.Code
	}{
		{"no peer", context.Background(), codes.PermissionDenied},
		{"plain addr", peer.NewContext(context.Background(), &peer.Peer{Addr: addr}), codes.PermissionDenied},
		{"denied", peer.NewContext(context.Background(), &peer.Peer{Addr: ipc.PeerAddr{Addr: addr, UID: 1002}}), codes.PermissionDenied},
		{"allowed", peer.NewContext(context.Background(), &peer.Peer{Addr: ipc.PeerAddr{Addr: addr, Allowed: true}}), codes.OK},
	}
	for _, tt := range tests {
		_, err := authUnary(tt.ctx, nil, &grpc.UnaryServerInfo{}, handler)
		if got := status.Code(err); got != tt.want {
			t.Errorf("%s: code = %v, want %v", tt.name, got, tt.want)
		}
	}
}
