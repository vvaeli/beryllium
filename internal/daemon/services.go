package daemon

import (
	"context"
	"runtime"
	"time"

	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/version"
	"google.golang.org/protobuf/types/known/durationpb"
)

type daemonService struct {
	berylliumv1.UnimplementedDaemonServiceServer
	d *Daemon
}

func (s *daemonService) GetVersion(context.Context, *berylliumv1.GetVersionRequest) (*berylliumv1.GetVersionResponse, error) {
	return &berylliumv1.GetVersionResponse{
		Version:   version.Version,
		Commit:    version.Commit,
		BuildDate: version.Date,
		Os:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		// Cores are reported once the core manager exists (ROADMAP 5.x).
	}, nil
}

func (s *daemonService) Health(context.Context, *berylliumv1.HealthRequest) (*berylliumv1.HealthResponse, error) {
	return &berylliumv1.HealthResponse{
		Ok:     true,
		Uptime: durationpb.New(time.Since(s.d.started)),
	}, nil
}

func (s *daemonService) Shutdown(context.Context, *berylliumv1.ShutdownRequest) (*berylliumv1.ShutdownResponse, error) {
	s.d.log.Info("shutdown requested over IPC")
	// Respond first; Run stops the server after this RPC completes.
	s.d.requestShutdown()
	return &berylliumv1.ShutdownResponse{}, nil
}

// Services below are implemented in later phases (ROADMAP 4–7) and return
// codes.Unimplemented until then.

type subscriptionService struct {
	berylliumv1.UnimplementedSubscriptionServiceServer
}

type connectionService struct {
	berylliumv1.UnimplementedConnectionServiceServer
}

type testService struct {
	berylliumv1.UnimplementedTestServiceServer
}

type settingsService struct {
	berylliumv1.UnimplementedSettingsServiceServer
}

type logService struct {
	berylliumv1.UnimplementedLogServiceServer
}
