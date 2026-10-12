package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/vvaeli/beryllium/internal/model"
	"github.com/vvaeli/beryllium/internal/routing"
)

// DefaultMixedPort is the preferred local HTTP+SOCKS5 port; a free one is
// used when it is taken.
const DefaultMixedPort = 2080

// State of the runtime.
type State string

// Runtime states.
const (
	StateDisconnected State = "disconnected"
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateRecovering   State = "recovering"
	StateFailed       State = "failed"
)

// Status is a snapshot of the runtime.
type Status struct {
	State      State
	Server     *model.Server
	Core       Kind
	Reason     string
	LocalProxy string
	// TUN is set while the chain runs with a TUN inbound.
	TUN      bool
	Since    time.Time
	Restarts int
	// Warnings from building the routing config (e.g. missing geo tags).
	Warnings []string
	Err      error
}

// ConnectOptions select how a server is run.
type ConnectOptions struct {
	// Core overrides automatic core selection.
	Core Kind
	// TUN captures all system traffic; needs root/Administrator.
	TUN *TUN
	// Routing is built by internal/routing; nil proxies everything.
	Routing *routing.Plan
}

// ErrTUNPrivileges is returned when TUN is requested by an unprivileged
// daemon.
var ErrTUNPrivileges = errors.New("TUN mode needs the daemon to run as root (Administrator on Windows); install it as a service with `sudo berylliumd install`")

// Traffic counters and rates from the front core.
type Traffic struct {
	Upload, Download         uint64
	UploadRate, DownloadRate uint64
}

// Options configure a Runtime.
type Options struct {
	Binaries *Binaries
	// WorkDir holds generated configs (they contain credentials) and pids.
	WorkDir   string
	Log       *slog.Logger
	MixedPort int
	// CoreLogLevel is debug, info, warn (default) or error; core output is
	// forwarded to Log.
	CoreLogLevel string
	// Restart policy for crashed cores.
	MaxRestarts   int
	RestartWindow time.Duration
}

// Runtime runs at most one proxy chain at a time.
type Runtime struct {
	opts Options

	mu     sync.Mutex
	status Status
	sess   *session
	last   trafficSample
}

type session struct {
	srv       model.Server
	opts      ConnectOptions
	choice    Choice
	mixedPort int
	backend   int
	apiPort   int
	apiSecret string
	procs     []*Process
	stop      chan struct{}
	failures  []time.Time
}

type trafficSample struct {
	at       time.Time
	up, down uint64
}

// New prepares a runtime and kills cores orphaned by a previous crash.
func New(o Options) *Runtime {
	// Cores run inside WorkDir/run, so config paths passed to them must
	// not be relative.
	if abs, err := filepath.Abs(o.WorkDir); err == nil {
		o.WorkDir = abs
	}
	if o.MixedPort == 0 {
		o.MixedPort = DefaultMixedPort
	}
	switch o.CoreLogLevel {
	case "debug", "info", "warn", "error":
	default:
		o.CoreLogLevel = "warn"
	}
	if o.MaxRestarts == 0 {
		o.MaxRestarts = 5
	}
	if o.RestartWindow == 0 {
		o.RestartWindow = 2 * time.Minute
	}
	r := &Runtime{opts: o, status: Status{State: StateDisconnected}}
	if pids, err := r.readPIDs(); err == nil {
		killOrphans(pids)
	}
	_ = os.Remove(r.pidFile())
	return r
}

// Status returns the current state.
func (r *Runtime) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

// Connect starts srv on the chosen core, replacing any running chain.
func (r *Runtime) Connect(ctx context.Context, srv model.Server, o ConnectOptions) (Status, error) {
	choice, err := Choose(&srv, o.Core, r.opts.Binaries.Installed)
	if err != nil {
		return r.Status(), err
	}
	if o.TUN != nil && !privileged() {
		return r.Status(), ErrTUNPrivileges
	}
	r.Disconnect()

	r.mu.Lock()
	r.status = Status{State: StateConnecting, Server: &srv, Core: choice.Kind, Reason: choice.Reason, TUN: o.TUN != nil}
	r.mu.Unlock()

	s := &session{srv: srv, opts: o, choice: choice, stop: make(chan struct{})}
	err = r.prepare(s)
	if err == nil {
		err = r.launch(ctx, s)
	}
	if err != nil {
		r.mu.Lock()
		r.status = Status{State: StateFailed, Server: &srv, Core: choice.Kind, Reason: choice.Reason, TUN: o.TUN != nil, Err: err}
		st := r.status
		r.mu.Unlock()
		return st, err
	}

	r.mu.Lock()
	r.sess = s
	r.last = trafficSample{}
	r.status = Status{State: StateConnected, Server: &srv, Core: choice.Kind, Reason: choice.Reason,
		LocalProxy: fmt.Sprintf("127.0.0.1:%d", s.mixedPort), TUN: o.TUN != nil, Since: time.Now()}
	if o.Routing != nil {
		r.status.Warnings = o.Routing.Warnings
	}
	st := r.status
	r.mu.Unlock()
	go r.monitor(s)
	r.opts.Log.Info("connected", "server", srv.Name, "core", choice.Kind, "proxy", st.LocalProxy, "tun", st.TUN)
	return st, nil
}

// Reconfigure restarts the running chain with new options, keeping the
// server and, unless o.Core is set, the core. It does nothing when
// disconnected.
func (r *Runtime) Reconfigure(ctx context.Context, o ConnectOptions) (Status, error) {
	r.mu.Lock()
	s := r.sess
	r.mu.Unlock()
	if s == nil {
		return r.Status(), nil
	}
	if o.Core == "" {
		o.Core = s.choice.Kind
	}
	return r.Connect(ctx, s.srv, o)
}

// Options returns the options of the running chain.
func (r *Runtime) Options() (ConnectOptions, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sess == nil {
		return ConnectOptions{}, false
	}
	return r.sess.opts, true
}

// Disconnect stops the running chain, if any.
func (r *Runtime) Disconnect() Status {
	r.mu.Lock()
	s := r.sess
	r.sess = nil
	r.mu.Unlock()
	if s != nil {
		close(s.stop)
		stopAll(s.procs)
		_ = os.Remove(r.pidFile())
		r.opts.Log.Info("disconnected")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status.State != StateFailed || s != nil {
		r.status = Status{State: StateDisconnected}
	}
	return r.status
}

// Close stops everything; the runtime can't be reused afterwards.
func (r *Runtime) Close() { r.Disconnect() }

// prepare allocates ports and writes configs for s.
func (r *Runtime) prepare(s *session) error {
	dir := r.runDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var err error
	s.mixedPort = r.opts.MixedPort
	if !portFree(s.mixedPort) {
		if s.mixedPort, err = freePort(); err != nil {
			return err
		}
	}
	if s.apiPort, err = freePort(); err != nil {
		return err
	}
	secret := make([]byte, 16)
	_, _ = rand.Read(secret)
	s.apiSecret = hex.EncodeToString(secret)

	level := r.opts.CoreLogLevel
	front := singBoxFront{MixedPort: s.mixedPort, APIPort: s.apiPort, APISecret: s.apiSecret, LogLevel: level,
		TUN: s.opts.TUN, Routing: s.opts.Routing}
	if s.opts.TUN != nil {
		front.DirectProcesses = r.directProcesses()
	}
	switch s.choice.Kind {
	case SingBox:
		front.Server = &s.srv
	case Xray, Mihomo:
		if s.backend, err = freePort(); err != nil {
			return err
		}
		front.BackendPort = s.backend
		var cfg []byte
		if s.choice.Kind == Xray {
			cfg, err = xrayConfig(&s.srv, s.backend, xrayLevel(level))
		} else {
			cfg, err = mihomoConfig(&s.srv, s.backend, xrayLevel(level))
		}
		if err != nil {
			return err
		}
		if err := writeSecret(r.configPath(s.choice.Kind), cfg); err != nil {
			return err
		}
	}
	cfg, err := singBoxConfig(front)
	if err != nil {
		return err
	}
	return writeSecret(r.configPath(SingBox), cfg)
}

// launch starts the backend (if any) and then the sing-box front.
func (r *Runtime) launch(ctx context.Context, s *session) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var procs []*Process
	start := func(k Kind, port int) error {
		p, err := startProcess(k, r.opts.Binaries.Path(k), r.args(k), r.runDir(), r.opts.Log)
		if err != nil {
			return err
		}
		procs = append(procs, p)
		return p.waitListening(ctx, fmt.Sprintf("127.0.0.1:%d", port))
	}
	var err error
	if s.backend != 0 {
		err = start(s.choice.Kind, s.backend)
	}
	if err == nil {
		err = start(SingBox, s.mixedPort)
	}
	if err != nil {
		stopAll(procs)
		return err
	}
	s.procs = procs
	r.writePIDs(procs)
	return nil
}

// monitor restarts the chain when a core exits unexpectedly, giving up
// after MaxRestarts failures within RestartWindow.
func (r *Runtime) monitor(s *session) {
	for {
		exited := make(chan *Process, len(s.procs))
		for _, p := range s.procs {
			go func(p *Process) {
				select {
				case <-p.Done():
					exited <- p
				case <-s.stop:
				}
			}(p)
		}
		var dead *Process
		select {
		case <-s.stop:
			return
		case dead = <-exited:
		}
		r.opts.Log.Warn("core exited unexpectedly", "core", dead.Kind, "output", lastLine(dead.Tail()))
		stopAll(s.procs)

		now := time.Now()
		recent := s.failures[:0]
		for _, t := range s.failures {
			if now.Sub(t) < r.opts.RestartWindow {
				recent = append(recent, t)
			}
		}
		recent = append(recent, now)
		s.failures = recent
		if len(s.failures) > r.opts.MaxRestarts {
			r.fail(s, fmt.Errorf("%s keeps crashing: %s", dead.Kind, lastLine(dead.Tail())))
			return
		}
		r.setState(s, StateRecovering, nil)
		backoff := time.Second << (len(s.failures) - 1)
		select {
		case <-s.stop:
			return
		case <-time.After(backoff):
		}
		if err := r.launch(context.Background(), s); err != nil {
			r.opts.Log.Warn("restart failed", "err", err)
			s.procs = nil
			s.failures = append(s.failures, time.Now())
			if len(s.failures) > r.opts.MaxRestarts {
				r.fail(s, err)
				return
			}
			continue
		}
		r.mu.Lock()
		if r.sess == s {
			r.status.State = StateConnected
			r.status.Restarts++
			r.status.Err = nil
		}
		r.mu.Unlock()
	}
}

func (r *Runtime) setState(s *session, st State, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sess == s {
		r.status.State, r.status.Err = st, err
	}
}

func (r *Runtime) fail(s *session, err error) {
	r.opts.Log.Error("giving up on core", "err", err)
	r.setState(s, StateFailed, err)
	r.mu.Lock()
	if r.sess == s {
		r.sess = nil
	}
	r.mu.Unlock()
	_ = os.Remove(r.pidFile())
}

// Traffic reads totals from the sing-box Clash API and derives rates from
// the previous call.
func (r *Runtime) Traffic(ctx context.Context) (Traffic, error) {
	r.mu.Lock()
	s := r.sess
	r.mu.Unlock()
	if s == nil {
		return Traffic{}, errors.New("not connected")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/connections", s.apiPort), nil)
	req.Header.Set("Authorization", "Bearer "+s.apiSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Traffic{}, err
	}
	defer resp.Body.Close()
	var body struct {
		Up   uint64 `json:"uploadTotal"`
		Down uint64 `json:"downloadTotal"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Traffic{}, err
	}
	t := Traffic{Upload: body.Up, Download: body.Down}
	now := time.Now()
	r.mu.Lock()
	if prev := r.last; !prev.at.IsZero() && body.Up >= prev.up && body.Down >= prev.down {
		if dt := now.Sub(prev.at).Seconds(); dt > 0 {
			t.UploadRate = uint64(float64(body.Up-prev.up) / dt)
			t.DownloadRate = uint64(float64(body.Down-prev.down) / dt)
		}
	}
	r.last = trafficSample{at: now, up: body.Up, down: body.Down}
	r.mu.Unlock()
	return t, nil
}

// DefaultTestURLs are probed by URLTest when no URL is given.
var DefaultTestURLs = []string{"https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"}

// URLTest fetches target through the local proxy and returns the latency.
// With no target, the first default URL that responds counts.
func (r *Runtime) URLTest(ctx context.Context, target string) (time.Duration, error) {
	st := r.Status()
	if st.State != StateConnected {
		return 0, errors.New("not connected")
	}
	proxy, _ := url.Parse("http://" + st.LocalProxy)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true},
		Timeout:   10 * time.Second,
	}
	targets := DefaultTestURLs
	if target != "" {
		targets = []string{target}
	}
	var lastErr error
	for _, u := range targets {
		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return 0, err
		}
		resp, err := client.Do(req)
		if err != nil {
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err
			}
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		return elapsed(start), nil
	}
	return 0, lastErr
}

// xrayLevel maps sing-box log levels to Xray's and mihomo's names.
func xrayLevel(l string) string {
	if l == "warn" {
		return "warning"
	}
	return l
}

// directProcesses must bypass TUN: the cores (backends dial the server
// themselves; sing-box also runs latency tests) and the daemon (geo and
// subscription downloads).
func (r *Runtime) directProcesses() []string {
	// The OS reports resolved paths, so symlinks (e.g. a linked cores dir)
	// must be resolved too.
	resolve := func(p string) string {
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			return resolved
		}
		return p
	}
	var out []string
	for _, k := range Kinds {
		out = append(out, resolve(r.opts.Binaries.Path(k)))
	}
	if exe, err := os.Executable(); err == nil {
		out = append(out, resolve(exe))
	}
	return out
}

func (r *Runtime) args(k Kind) []string {
	switch k {
	case SingBox:
		return []string{"run", "-c", r.configPath(k), "-D", r.runDir(), "--disable-color"}
	case Xray:
		return []string{"run", "-c", r.configPath(k)}
	default:
		return []string{"-d", r.runDir(), "-f", r.configPath(k)}
	}
}

func (r *Runtime) runDir() string  { return filepath.Join(r.opts.WorkDir, "run") }
func (r *Runtime) pidFile() string { return filepath.Join(r.runDir(), "pids.json") }

func (r *Runtime) configPath(k Kind) string {
	if k == Mihomo {
		return filepath.Join(r.runDir(), "mihomo.yaml")
	}
	return filepath.Join(r.runDir(), string(k)+".json")
}

func (r *Runtime) writePIDs(procs []*Process) {
	m := map[string]string{}
	for _, p := range procs {
		m[strconv.Itoa(p.PID())] = r.opts.Binaries.Path(p.Kind)
	}
	raw, _ := json.Marshal(m)
	_ = writeSecret(r.pidFile(), raw)
}

func (r *Runtime) readPIDs() (map[int]string, error) {
	raw, err := os.ReadFile(r.pidFile())
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	out := map[int]string{}
	for k, v := range m {
		if pid, err := strconv.Atoi(k); err == nil && pid > 0 {
			out[pid] = v
		}
	}
	return out, nil
}

func stopAll(procs []*Process) {
	for i := len(procs) - 1; i >= 0; i-- { // front first
		procs[i].Stop(3 * time.Second)
	}
}

func writeSecret(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
