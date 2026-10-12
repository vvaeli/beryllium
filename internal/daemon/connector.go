package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/core"
	"github.com/vvaeli/beryllium/internal/ipc"
	"github.com/vvaeli/beryllium/internal/model"
	"github.com/vvaeli/beryllium/internal/paths"
	"github.com/vvaeli/beryllium/internal/routing"
	"github.com/vvaeli/beryllium/internal/subscription"
	"github.com/vvaeli/beryllium/internal/sysproxy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// connector owns the connection lifecycle on top of core.Runtime: the
// mode (TUN, system proxy, local proxy), the routing plan, the OS proxy
// settings and live reconfiguration when settings or routing change.
type connector struct {
	log      *slog.Logger
	paths    paths.Paths
	rt       *core.Runtime
	bins     *core.Binaries
	subs     *subscription.Manager
	routes   *routing.Manager
	settings *settingsStore
	pinger   *core.Pinger
	latency  *latencyCache

	// mu serializes connect, disconnect and reconfigure.
	mu    sync.Mutex
	mode  berylliumv1.Mode
	subID string
	// proxy is the applied OS proxy (nil when not set).
	proxy *proxyMarker
}

// proxyMarker is persisted before the OS proxy is changed, so the previous
// settings are restored after a crash or reboot (ROADMAP 6.5).
type proxyMarker struct {
	Owner sysproxy.Owner  `json:"owner"`
	Saved json.RawMessage `json:"saved"`
	Port  int             `json:"port"`
}

func (c *connector) markerPath() string { return c.paths.StateFile("sysproxy.json") }

// restoreStale undoes OS proxy settings left by a previous run.
func (c *connector) restoreStale(ctx context.Context) {
	raw, err := os.ReadFile(c.markerPath())
	if err != nil {
		return
	}
	var m proxyMarker
	if err := json.Unmarshal(raw, &m); err == nil {
		if err := sysproxy.Restore(ctx, m.Owner, m.Saved); err != nil {
			c.log.Warn("restoring system proxy left by a previous run failed", "err", err)
			return
		}
		c.log.Info("restored system proxy settings left by a previous run")
	}
	_ = os.Remove(c.markerPath())
}

// owner is the user whose desktop gets the system proxy: the caller.
func owner(ctx context.Context) sysproxy.Owner {
	o := sysproxy.Owner{UID: -1}
	if p, ok := peer.FromContext(ctx); ok {
		if a, ok := p.Addr.(ipc.PeerAddr); ok && a.UID != uint32(os.Geteuid()) {
			o.UID = int(a.UID)
		}
	}
	return o
}

func (c *connector) connect(ctx context.Context, req *berylliumv1.ConnectRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	mode := req.GetMode()
	if mode == berylliumv1.Mode_MODE_UNSPECIFIED {
		mode = c.settings.get().GetMode()
	}
	srv, subID, err := c.pick(ctx, req.GetServerId(), req.GetSubscriptionId())
	if err != nil {
		return err
	}
	opts, err := c.options(mode)
	if err != nil {
		return err
	}
	opts.Core = kindFromProto[req.GetCore()]
	if opts.Core == "" {
		opts.Core = kindFromProto[c.settings.get().GetPreferredCore()]
		if _, err := core.Choose(&srv, opts.Core, c.bins.Installed); err != nil {
			opts.Core = "" // the preferred core can't run this server
		}
	}
	if _, err := c.rt.Connect(ctx, srv, opts); err != nil {
		c.restoreProxy(ctx)
		return coreErr(err)
	}
	c.mode, c.subID = mode, subID
	if err := c.syncProxy(ctx, owner(ctx)); err != nil {
		c.rt.Disconnect()
		return withReason(codes.FailedPrecondition, berylliumv1.ErrorReason_ERROR_REASON_SYSTEM_PROXY_FAILED, err)
	}
	routing.PruneRuleSets(c.ruleSetDir(), opts.Routing)
	return nil
}

func (c *connector) disconnect(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.restoreProxy(ctx)
	c.rt.Disconnect()
}

// reconfigure applies changed settings or routing to a live connection.
// mode is the new mode, or UNSPECIFIED to keep the current one.
func (c *connector) reconfigure(ctx context.Context, mode berylliumv1.Mode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.rt.Options(); !ok {
		return
	}
	if mode == berylliumv1.Mode_MODE_UNSPECIFIED {
		mode = c.mode
	}
	opts, err := c.options(mode)
	if err != nil {
		c.log.Warn("reconfigure failed", "err", err)
		return
	}
	if _, err := c.rt.Reconfigure(ctx, opts); err != nil {
		c.log.Warn("reconfigure failed", "err", err)
		c.restoreProxy(ctx)
		return
	}
	c.mode = mode
	o := sysproxy.Owner{UID: -1}
	if c.proxy != nil {
		o = c.proxy.Owner
	}
	if err := c.syncProxy(ctx, o); err != nil {
		c.log.Warn("system proxy failed after reconfigure", "err", err)
	}
	routing.PruneRuleSets(c.ruleSetDir(), opts.Routing)
	c.log.Info("connection reconfigured", "mode", modeName(mode))
}

// syncProxy makes the OS proxy match the mode: set (or re-pointed at a new
// port) in system proxy mode, restored otherwise. c.mu must be held.
func (c *connector) syncProxy(ctx context.Context, o sysproxy.Owner) error {
	st := c.rt.Status()
	if c.mode != berylliumv1.Mode_MODE_SYSTEM_PROXY || st.State != core.StateConnected {
		c.restoreProxy(ctx)
		return nil
	}
	host, portStr, _ := strings.Cut(st.LocalProxy, ":")
	port, _ := strconv.Atoi(portStr)
	if c.proxy != nil && c.proxy.Port == port && c.proxy.Owner == o {
		return nil
	}
	if c.proxy != nil && c.proxy.Owner != o {
		c.restoreProxy(ctx)
	}
	if c.proxy == nil {
		saved, err := sysproxy.Capture(ctx, o)
		if err != nil {
			return err
		}
		m := &proxyMarker{Owner: o, Saved: saved}
		raw, _ := json.Marshal(m)
		if err := os.WriteFile(c.markerPath(), raw, 0o600); err != nil {
			return err
		}
		c.proxy = m
	}
	if err := sysproxy.Apply(ctx, o, sysproxy.Config{Host: host, Port: port, Bypass: sysproxy.DefaultBypass}); err != nil {
		c.restoreProxy(ctx)
		return err
	}
	c.proxy.Port = port
	c.log.Info("system proxy set", "proxy", st.LocalProxy)
	return nil
}

// restoreProxy puts back the OS proxy settings; c.mu must be held.
func (c *connector) restoreProxy(ctx context.Context) {
	if c.proxy == nil {
		return
	}
	if err := sysproxy.Restore(ctx, c.proxy.Owner, c.proxy.Saved); err != nil {
		c.log.Warn("restoring system proxy failed; will retry on next start", "err", err)
	} else {
		_ = os.Remove(c.markerPath())
		c.log.Info("system proxy restored")
	}
	c.proxy = nil
}

func (c *connector) ruleSetDir() string { return c.paths.StateFile("rulesets") }

// options builds the core options for mode from settings and the active
// routing profile.
func (c *connector) options(mode berylliumv1.Mode) (core.ConnectOptions, error) {
	set := c.settings.get()
	rec, site, ip := c.routes.Active()
	in := routing.Input{
		GeoSite: site, GeoIP: ip,
		DNS: routing.DNS{
			Remote: set.GetDns().GetRemoteDns(),
			Direct: set.GetDns().GetDirectDns(),
			FakeIP: set.GetDns().GetFakeIp(),
			IPv6:   set.GetDns().GetIpv6() == berylliumv1.Ipv6Mode_IPV6_MODE_TUNNEL,
		},
		TUN:        mode == berylliumv1.Mode_MODE_TUN,
		RuleSetDir: c.ruleSetDir(),
	}
	if rec.ID != "" {
		p := rec.Profile
		in.Profile = &p
	}
	if c.bins.Installed(core.SingBox) {
		in.Compile = c.bins.CompileRuleSet
	}
	for _, r := range set.GetRouting().GetRules() {
		in.Rules = append(in.Rules, ruleFromProto(r))
	}
	plan, err := routing.Build(in)
	if err != nil {
		return core.ConnectOptions{}, status.Error(codes.FailedPrecondition, err.Error())
	}
	for _, w := range plan.Warnings {
		c.log.Warn("routing", "profile", rec.Profile.Name, "warning", w)
	}
	opts := core.ConnectOptions{Routing: plan}
	if mode == berylliumv1.Mode_MODE_TUN {
		opts.TUN = &core.TUN{}
	}
	return opts, nil
}

// pick resolves the server to connect to; with no ID it auto-selects the
// lowest HTTP latency, measuring first when nothing is cached.
func (c *connector) pick(ctx context.Context, serverID, subID string) (model.Server, string, error) {
	if serverID != "" {
		srv, sub, err := c.subs.Server(serverID)
		if err != nil {
			return model.Server{}, "", subErr(err)
		}
		return srv, sub, nil
	}
	servers, err := c.subs.Servers(subID)
	if err != nil {
		return model.Server{}, "", subErr(err)
	}
	if len(servers) == 0 {
		return model.Server{}, "", status.Error(codes.FailedPrecondition, "no servers; add a subscription first")
	}
	best, ok := c.latency.fastest(servers)
	if !ok {
		results := make(chan core.PingResult)
		go func() {
			c.pinger.Ping(ctx, servers, core.PingOptions{Method: core.PingHTTP, Timeout: defaultPingTimeout}, results)
			close(results)
		}()
		for r := range results {
			c.latency.put(r.ServerID, r.Latency)
		}
		if best, ok = c.latency.fastest(servers); !ok {
			return model.Server{}, "", withReason(codes.FailedPrecondition, berylliumv1.ErrorReason_ERROR_REASON_NETWORK_UNAVAILABLE,
				errors.New("no server responded to the latency test"))
		}
	}
	srv, sub, err := c.subs.Server(best.ID)
	if err != nil {
		return model.Server{}, "", subErr(err)
	}
	c.log.Info("auto-selected server", "server", srv.Name)
	return srv, sub, nil
}

// settingsChanged reconfigures a live connection when something it uses
// changed. Setting the mode explicitly switches a connection that runs in
// another mode (e.g. started with `connect --mode tun`), even when the
// stored default didn't change.
func (c *connector) settingsChanged(old, cur *berylliumv1.Settings, paths []string) {
	mode := berylliumv1.Mode_MODE_UNSPECIFIED
	c.mu.Lock()
	live := c.mode
	c.mu.Unlock()
	if (len(paths) == 0 || slices.Contains(paths, "mode")) && cur.GetMode() != live {
		mode = cur.GetMode()
	} else if proto.Equal(old.GetRouting(), cur.GetRouting()) && proto.Equal(old.GetDns(), cur.GetDns()) {
		return
	}
	// Synchronous, so UpdateSettings returns once the change is live.
	c.reconfigure(context.Background(), mode)
}

// currentMode is the mode of the live connection.
func (c *connector) currentMode() (berylliumv1.Mode, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mode, c.subID
}

func modeName(m berylliumv1.Mode) string {
	return strings.ToLower(strings.TrimPrefix(m.String(), "MODE_"))
}

// shutdown restores the OS proxy and stops cores.
func (c *connector) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c.disconnect(ctx)
}
