// Package daemon wires the IPC listener, gRPC services and lifecycle of
// berylliumd.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/core"
	"github.com/vvaeli/beryllium/internal/ipc"
	"github.com/vvaeli/beryllium/internal/netwatch"
	"github.com/vvaeli/beryllium/internal/paths"
	"github.com/vvaeli/beryllium/internal/routing"
	"github.com/vvaeli/beryllium/internal/store"
	"github.com/vvaeli/beryllium/internal/subscription"
	"github.com/vvaeli/beryllium/internal/version"
	"github.com/vvaeli/beryllium/internal/watchdog"
	"google.golang.org/grpc"
)

// IPCGroup is the Linux group whose members may control the daemon.
const IPCGroup = "beryllium"

// gracePeriod bounds how long in-flight RPCs (including streams) may run
// after shutdown starts.
const gracePeriod = 5 * time.Second

// DefaultUserAgent is sent when fetching subscriptions. Panels pick the
// response format by User-Agent, and some (e.g. Remnawave) send Happ-style
// extras such as the `routing` header only to Happ, so a Happ-compatible
// prefix is used.
var DefaultUserAgent = "Happ/4.0.0 (Beryllium/" + version.Version + ")"

// Options configure a Daemon.
type Options struct {
	Paths paths.Paths
	Log   *slog.Logger
	// UserAgent for subscription downloads; empty uses DefaultUserAgent.
	UserAgent string
	// CoreLogLevel for sing-box/Xray/mihomo (debug|info|warn|error);
	// empty means warn.
	CoreLogLevel string

	// For hermetic tests: ProbeURLs replace the public generate_204
	// endpoints the watchdog checks the tunnel with, Reach replaces the
	// direct connectivity check, and NoSystemEvents turns off sleep, wake
	// and network change monitoring.
	ProbeURLs      []string
	Reach          func(context.Context) watchdog.Reach
	NoSystemEvents bool
}

// Daemon is a running berylliumd instance.
type Daemon struct {
	paths     paths.Paths
	log       *slog.Logger
	userAgent string
	coreLevel string
	opts      Options
	started   time.Time
	subs      *subscription.Manager
	rt        *core.Runtime
	pinger    *core.Pinger
	latency   *latencyCache
	settings  *settingsStore
	routes    *routing.Manager
	conn      *connector
	wd        *watchdog.Watchdog

	shutdownOnce sync.Once
	shutdownCh   chan struct{}
}

// New prepares a daemon; nothing is opened until Run.
func New(o Options) *Daemon {
	ua := o.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}
	return &Daemon{paths: o.Paths, log: o.Log, userAgent: ua, coreLevel: o.CoreLogLevel, opts: o, shutdownCh: make(chan struct{})}
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

	d.subs, err = subscription.NewManager(
		store.Open[subscription.State](d.paths.StateFile("subscriptions.json")),
		subscription.NewFetcher(d.userAgent), d.log)
	if err != nil {
		return err
	}

	bins := core.LoadBinaries(d.paths.CoresDir)
	for _, k := range core.Kinds {
		if !bins.Installed(k) {
			d.log.Warn("core not installed", "core", k, "dir", d.paths.CoresDir)
		}
	}
	d.rt = core.New(core.Options{Binaries: bins, WorkDir: d.paths.StateDir, Log: d.log, CoreLogLevel: d.coreLevel})
	d.pinger = &core.Pinger{Binaries: bins, WorkDir: d.paths.StateDir}
	d.latency = newLatencyCache()

	if d.settings, err = openSettings(store.Open[json.RawMessage](d.paths.StateFile("settings.json"))); err != nil {
		return err
	}
	d.routes, err = routing.NewManager(store.Open[routing.State](d.paths.StateFile("routing.json")),
		&routing.GeoCache{Dir: d.paths.StateFile("geo")}, d.log)
	if err != nil {
		return err
	}
	d.conn = &connector{log: d.log, paths: d.paths, rt: d.rt, bins: bins, subs: d.subs, routes: d.routes,
		settings: d.settings, pinger: d.pinger, latency: d.latency, probeURLs: d.opts.ProbeURLs, reach: d.opts.Reach}
	d.wd = watchdog.New(recoveryTarget{d.conn}, d.conn.watchdogConfig, nil, d.log)
	d.conn.wd = d.wd
	d.conn.restoreStale(ctx)
	defer d.conn.shutdown()
	d.settings.onChange = d.conn.settingsChanged
	d.routes.OnChange = func() { d.conn.reconfigure(context.Background(), berylliumv1.Mode_MODE_UNSPECIFIED) }
	d.subs.OnUpdate = func(r subscription.Record) {
		if r.Routing != "" && d.settings.get().GetRouting().GetApplyProviderRouting() {
			d.routes.ImportFromSubscription(context.Background(), r.ID, r.Routing)
		}
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

	bgCtx, stopBackground := context.WithCancel(ctx)
	defer stopBackground()
	go d.subs.Run(bgCtx, time.Minute)
	go d.routes.Run(bgCtx)
	go d.wd.Run(bgCtx)
	if !d.opts.NoSystemEvents {
		go netwatch.Run(bgCtx, d.log, core.TUNPrefixes(), netwatch.Events{
			Sleep: func() { d.wd.Sleep(bgCtx) },
			Wake: func(source string) {
				d.log.Info("woke up", "detected_by", source)
				d.wd.Trigger(bgCtx, watchdog.TriggerWake, false)
			},
			NetChange: func(_, _ netwatch.Network) { d.wd.Trigger(bgCtx, watchdog.TriggerNetChange, false) },
		})
	}

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
	stopBackground()
	stopped := make(chan struct{})
	go func() { srv.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(gracePeriod):
		srv.Stop()
	}
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
	berylliumv1.RegisterSubscriptionServiceServer(s, &subscriptionService{subs: d.subs, latency: d.latency, routes: d.routes})
	berylliumv1.RegisterConnectionServiceServer(s, &connectionService{c: d.conn, rt: d.rt, latency: d.latency})
	berylliumv1.RegisterTestServiceServer(s, &testService{rt: d.rt, subs: d.subs, pinger: d.pinger, latency: d.latency})
	berylliumv1.RegisterSettingsServiceServer(s, &settingsService{s: d.settings})
	berylliumv1.RegisterLogServiceServer(s, &logService{})
	berylliumv1.RegisterRoutingServiceServer(s, &routingService{routes: d.routes})
}
