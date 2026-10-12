// Package daemon wires the IPC listener, gRPC services and lifecycle of
// berylliumd.
package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/ipc"
	"github.com/vvaeli/beryllium/internal/paths"
	"google.golang.org/grpc"
)

// IPCGroup is the Linux group whose members may control the daemon.
const IPCGroup = "beryllium"

// gracePeriod bounds how long in-flight RPCs (including streams) may run
// after shutdown starts.
const gracePeriod = 5 * time.Second

// Daemon is a running berylliumd instance.
type Daemon struct {
	paths   paths.Paths
	log     *slog.Logger
	started time.Time

	shutdownOnce sync.Once
	shutdownCh   chan struct{}
}

// New prepares a daemon; nothing is opened until Run.
func New(p paths.Paths, log *slog.Logger) *Daemon {
	return &Daemon{paths: p, log: log, shutdownCh: make(chan struct{})}
}

// Run serves the API until ctx is canceled or a Shutdown RPC arrives, then
// stops gracefully. It returns nil on a clean shutdown.
func (d *Daemon) Run(ctx context.Context) error {
	d.started = time.Now()
	if err := os.MkdirAll(d.paths.StateDir, 0o700); err != nil {
		return err
	}
	cfg, err := ConfigStore(d.paths).Load()
	if err != nil {
		return err
	}

	ln, err := ipc.Listen(d.paths.Socket, ipc.Access{
		UIDs:   cfg.AllowedUIDs,
		Group:  IPCGroup,
		SIDs:   cfg.AllowedSIDs,
		Logger: d.log,
	})
	if err != nil {
		return err
	}

	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(authUnary),
		grpc.ChainStreamInterceptor(authStream),
	)
	d.register(srv)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	d.log.Info("daemon started", "socket", d.paths.Socket, "pid", os.Getpid())

	select {
	case <-ctx.Done():
	case <-d.shutdownCh:
	case err := <-serveErr:
		return err
	}

	d.log.Info("daemon stopping")
	stopped := make(chan struct{})
	go func() { srv.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(gracePeriod):
		srv.Stop()
	}
	// Later phases restore system proxy settings and stop cores here.
	if err := <-serveErr; err != nil && !errors.Is(err, grpc.ErrServerStopped) && !errors.Is(err, net.ErrClosed) {
		return err
	}
	d.log.Info("daemon stopped")
	return nil
}

// requestShutdown makes Run return; safe to call multiple times.
func (d *Daemon) requestShutdown() {
	d.shutdownOnce.Do(func() { close(d.shutdownCh) })
}

func (d *Daemon) register(s *grpc.Server) {
	berylliumv1.RegisterDaemonServiceServer(s, &daemonService{d: d})
	berylliumv1.RegisterSubscriptionServiceServer(s, &subscriptionService{})
	berylliumv1.RegisterConnectionServiceServer(s, &connectionService{})
	berylliumv1.RegisterTestServiceServer(s, &testService{})
	berylliumv1.RegisterSettingsServiceServer(s, &settingsService{})
	berylliumv1.RegisterLogServiceServer(s, &logService{})
	berylliumv1.RegisterRoutingServiceServer(s, &routingService{})
}
