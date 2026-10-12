// Command berylliumd is the privileged Beryllium daemon.
//
//	berylliumd [flags]                    run (in foreground or under the service manager)
//	berylliumd [flags] install            register the system service; the invoking user gets IPC access
//	berylliumd uninstall|start|stop|restart|status
//
// Service managers: systemd, OpenRC, SysV, launchd and Windows services via
// kardianos/service; runit, dinit and s6 natively (initsys_linux.go).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"slices"
	"time"

	"github.com/kardianos/service"
	"github.com/vvaeli/beryllium/internal/daemon"
	"github.com/vvaeli/beryllium/internal/logging"
	"github.com/vvaeli/beryllium/internal/paths"
	"github.com/vvaeli/beryllium/internal/sysproxy"
	"github.com/vvaeli/beryllium/internal/version"
)

func main() {
	// Windows: the daemon (SYSTEM) re-runs itself in the user's session to
	// change their proxy settings.
	if len(os.Args) > 1 && os.Args[1] == sysproxy.HelperArg {
		os.Exit(sysproxy.HelperMain(os.Args[2:], os.Stdin, os.Stdout))
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "berylliumd:", err)
		os.Exit(1)
	}
}

func run() error {
	p := paths.Default()
	flag.StringVar(&p.StateDir, "config-dir", p.StateDir, "state directory")
	flag.StringVar(&p.LogDir, "log-dir", p.LogDir, "log directory")
	flag.StringVar(&p.Socket, "socket", p.Socket, "IPC socket path or named pipe")
	flag.StringVar(&p.CoresDir, "cores-dir", p.CoresDir, "directory with sing-box, xray and mihomo executables")
	logLevel := flag.String("log-level", "info", "debug|info|warn|error")
	foreground := flag.Bool("foreground", false, "also log to stderr")
	showVersion := flag.Bool("version", false, "print version and exit")
	userAgent := flag.String("user-agent", "", "User-Agent for subscription downloads (default: Happ-compatible)")
	flag.Parse()

	if *showVersion {
		fmt.Println("berylliumd", version.String())
		return nil
	}
	level, err := logging.ParseLevel(*logLevel)
	if err != nil {
		return err
	}
	if p, err = p.Abs(); err != nil {
		return err
	}
	// Store absolute paths in the flags too, so `install` bakes them into
	// the service definition (services start in another directory).
	for name, v := range map[string]string{"config-dir": p.StateDir, "log-dir": p.LogDir, "socket": p.Socket, "cores-dir": p.CoresDir} {
		if isSet(name) {
			_ = flag.Set(name, v)
		}
	}

	// Flags given at install time are baked into the service definition.
	var svcArgs []string
	flag.Visit(func(f *flag.Flag) { svcArgs = append(svcArgs, "-"+f.Name+"="+f.Value.String()) })

	prog := &program{paths: p, userAgent: *userAgent}
	svc, err := service.New(prog, serviceConfig(svcArgs))
	if err != nil {
		return err
	}

	if cmd := flag.Arg(0); cmd != "" {
		if in := nativeInit(); in != nil {
			return controlNative(in, cmd, p, svcArgs)
		}
		return control(svc, cmd, p)
	}

	if err := os.MkdirAll(p.LogDir, 0o755); err != nil {
		return fmt.Errorf("log dir: %w (run as root/admin or pass -config-dir, -log-dir, -socket)", err)
	}
	// journald captures stderr under systemd (INVOCATION_ID is set there).
	stderr := *foreground || service.Interactive() || os.Getenv("INVOCATION_ID") != ""
	log, closer := logging.Setup(logging.Options{Level: level, File: p.LogFile(), Stderr: stderr})
	defer closer.Close()
	slog.SetDefault(log)
	prog.log = log

	log.Info("berylliumd", "version", version.String(), "os", runtime.GOOS, "arch", runtime.GOARCH)
	return svc.Run()
}

func isSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
}

func serviceConfig(args []string) *service.Config {
	name := "berylliumd"
	if runtime.GOOS == "darwin" {
		name = "io.github.vvaeli.beryllium" // launchd label
	}
	return &service.Config{
		Name:        name,
		DisplayName: "Beryllium",
		Description: "Beryllium proxy/VPN daemon",
		Arguments:   args,
		Option: service.KeyValue{
			// systemd
			"Restart": "on-failure",
			// launchd
			"KeepAlive": true,
			"RunAtLoad": true,
			// Windows service recovery
			"OnFailure":              "restart",
			"OnFailureDelayDuration": "5s",
			"OnFailureResetPeriod":   60,
		},
	}
}

func control(svc service.Service, cmd string, p paths.Paths) error {
	switch cmd {
	case "install":
		if err := requireAdmin(); err != nil {
			return err
		}
		if err := grantInstallingUser(p); err != nil {
			return fmt.Errorf("record IPC access: %w", err)
		}
		if err := svc.Install(); err != nil {
			return err
		}
		fmt.Println("service installed; start it with: berylliumd start")
		return nil
	case "uninstall", "start", "stop", "restart":
		if err := requireAdmin(); err != nil {
			return err
		}
		return service.Control(svc, cmd)
	case "status":
		st, err := svc.Status()
		if err != nil {
			return err
		}
		switch st {
		case service.StatusRunning:
			fmt.Println("running")
		case service.StatusStopped:
			fmt.Println("stopped")
		default:
			fmt.Println("unknown")
		}
		return nil
	default:
		return fmt.Errorf("unknown command %q (want install|uninstall|start|stop|restart|status)", cmd)
	}
}

// controlNative handles runit, dinit and s6 (see initsys_linux.go).
func controlNative(in initSystem, cmd string, p paths.Paths, args []string) error {
	if cmd != "status" {
		if err := requireAdmin(); err != nil {
			return err
		}
	}
	switch cmd {
	case "install":
		if err := grantInstallingUser(p); err != nil {
			return fmt.Errorf("record IPC access: %w", err)
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if err := in.install(exe, args); err != nil {
			return err
		}
		fmt.Printf("%s service installed\n", in.name())
		return nil
	case "uninstall":
		return in.uninstall()
	case "start", "stop", "restart", "status":
		return in.control(cmd)
	}
	return fmt.Errorf("unknown command %q (want install|uninstall|start|stop|restart|status)", cmd)
}

// grantInstallingUser records the user who ran the install (via sudo/UAC)
// in daemon.json so their frontends can reach the IPC socket.
func grantInstallingUser(p paths.Paths) error {
	st := daemon.ConfigStore(p)
	cfg, err := st.Load()
	if err != nil {
		return err
	}
	uid, sid, ok := installingUser()
	if !ok {
		return nil
	}
	switch {
	case sid != "" && !slices.Contains(cfg.AllowedSIDs, sid):
		cfg.AllowedSIDs = append(cfg.AllowedSIDs, sid)
	case sid == "" && !slices.Contains(cfg.AllowedUIDs, uid):
		cfg.AllowedUIDs = append(cfg.AllowedUIDs, uid)
	default:
		return nil
	}
	return st.Save(cfg)
}

// program adapts Daemon to the service manager.
type program struct {
	paths     paths.Paths
	userAgent string
	log       *slog.Logger
	cancel    context.CancelFunc
	done      chan error
}

func (p *program) Start(service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan error, 1)
	d := daemon.New(daemon.Options{Paths: p.paths, Log: p.log, UserAgent: p.userAgent})
	go func() {
		err := d.Run(ctx)
		if ctx.Err() != nil { // stopped by the service manager
			p.done <- err
			return
		}
		// Run ended on its own: Shutdown RPC (nil) or a fatal error. Exit so
		// the service manager's restart policy applies.
		if err != nil {
			p.log.Error("daemon failed", "err", err)
			if errors.Is(err, os.ErrPermission) {
				p.log.Error("hint: run as root/admin or pass -config-dir, -log-dir, -socket")
			}
			os.Exit(1)
		}
		os.Exit(0)
	}()
	return nil
}

func (p *program) Stop(service.Service) error {
	p.cancel()
	select {
	case err := <-p.done:
		return err
	case <-time.After(15 * time.Second):
		return errors.New("timed out waiting for daemon to stop")
	}
}
