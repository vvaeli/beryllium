package daemon

import (
	"context"

	"github.com/vvaeli/beryllium/internal/ipc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// errUnauthorized is returned to peers that ipc marked as not allowed. The
// connection itself is accepted so the client gets a clear error to act on.
var errUnauthorized = status.Error(codes.PermissionDenied, "not allowed to control the Beryllium daemon")

func authorized(ctx context.Context) bool {
	p, ok := peer.FromContext(ctx)
	return ok && ipc.Authorized(p.Addr)
}

func authUnary(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	if !authorized(ctx) {
		return nil, errUnauthorized
	}
	return h(ctx, req)
}

func authStream(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
	if !authorized(ss.Context()) {
		return errUnauthorized
	}
	return h(srv, ss)
}
