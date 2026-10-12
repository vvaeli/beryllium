package daemon

import (
	"context"
	"runtime"
	"time"

	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/core"
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
		Cores:     s.cores(),
	}, nil
}

func (s *daemonService) cores() []*berylliumv1.CoreInfo {
	bins := core.LoadBinaries(s.d.paths.CoresDir)
	var out []*berylliumv1.CoreInfo
	for _, k := range core.Kinds {
		out = append(out, &berylliumv1.CoreInfo{Kind: kindToProto[k], Version: bins.Version(k), Installed: bins.Installed(k)})
	}
	return out
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

// Services below are implemented in later phases (ROADMAP 7) and return
// codes.Unimplemented until then.

type logService struct {
	berylliumv1.UnimplementedLogServiceServer
}
