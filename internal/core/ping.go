package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/vvaeli/beryllium/internal/model"
)

// PingMethod selects how latency is measured.
type PingMethod string

// Ping methods.
const (
	// PingHTTP fetches a URL through the server (full proxy chain).
	PingHTTP PingMethod = "http"
	// PingTCP times a TCP handshake to the server's address:port.
	PingTCP PingMethod = "tcp"
	// PingICMP sends an ICMP echo to the server's host.
	PingICMP PingMethod = "icmp"
)

// DefaultPingURL is plain HTTP on purpose, like Clash's url-test: an HTTPS
// target would add a TLS handshake with the test site itself, which says
// nothing about the tunnel.
const DefaultPingURL = "http://www.gstatic.com/generate_204"

// PingResult is the latency of one server, or why it couldn't be measured.
type PingResult struct {
	ServerID string
	Latency  time.Duration
	Err      error
}

// PingOptions configure a batch measurement.
type PingOptions struct {
	Method  PingMethod
	URL     string
	Timeout time.Duration
	// Parallel caps concurrent measurements.
	Parallel int
}

// Pinger measures server latency. HTTP measurements run in temporary core
// instances, independent of the active connection.
type Pinger struct {
	Binaries *Binaries
	WorkDir  string
}

// Ping measures every server and sends one result per server to out, in
// completion order. It returns when all results are sent.
func (p *Pinger) Ping(ctx context.Context, servers []model.Server, o PingOptions, out chan<- PingResult) {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Parallel <= 0 {
		o.Parallel = 16
	}
	if o.URL == "" {
		o.URL = DefaultPingURL
	}
	switch o.Method {
	case PingTCP:
		parallel(ctx, servers, o.Parallel, out, func(s *model.Server) (time.Duration, error) { return tcpPing(ctx, s, o.Timeout) })
	case PingICMP:
		parallel(ctx, servers, o.Parallel, out, func(s *model.Server) (time.Duration, error) { return icmpPing(ctx, s.Address, o.Timeout) })
	default:
		p.httpPing(ctx, servers, o, out)
	}
}

func parallel(ctx context.Context, servers []model.Server, n int, out chan<- PingResult, fn func(*model.Server) (time.Duration, error)) {
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i := range servers {
		s := &servers[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				out <- PingResult{ServerID: s.ID, Err: ctx.Err()}
				return
			}
			lat, err := fn(s)
			out <- PingResult{ServerID: s.ID, Latency: lat, Err: err}
		}()
	}
	wg.Wait()
}

func tcpPing(ctx context.Context, s *model.Server, timeout time.Duration) (time.Duration, error) {
	switch s.Protocol {
	case model.Hysteria2, model.TUIC, model.WireGuard, model.AmneziaWG:
		return 0, fmt.Errorf("TCP ping does not apply to %s (UDP); use http or icmp", s.Protocol)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Resolve first so DNS time isn't counted as latency.
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, s.Address)
	if err != nil {
		return 0, fmt.Errorf("resolve: %w", err)
	}
	var d net.Dialer
	start := time.Now()
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ips[0].IP.String(), strconv.Itoa(int(s.Port))))
	if err != nil {
		return 0, err
	}
	lat := elapsed(start)
	c.Close()
	return lat, nil
}

// httpPing starts one sing-box with a loopback mixed inbound per server
// (plus one Xray and one mihomo instance for servers sing-box can't run),
// then GETs the test URL through each inbound — the same request path a
// real app uses. sing-box's own Clash API delay test is not used: it adds
// a fixed ~1s on some outbounds and doesn't reflect real latency.
func (p *Pinger) httpPing(ctx context.Context, servers []model.Server, o PingOptions, out chan<- PingResult) {
	type entry struct {
		srv     *model.Server
		kind    Kind
		backend int
		port    int
	}
	var (
		entries []*entry
		byCore  = map[Kind][]*entry{}
	)
	for i := range servers {
		s := &servers[i]
		c, err := Choose(s, "", p.Binaries.Installed)
		if err != nil {
			out <- PingResult{ServerID: s.ID, Err: err}
			continue
		}
		e := &entry{srv: s, kind: c.Kind}
		entries = append(entries, e)
		byCore[c.Kind] = append(byCore[c.Kind], e)
	}
	if len(entries) == 0 {
		return
	}
	failAll := func(err error) {
		for _, e := range entries {
			out <- PingResult{ServerID: e.srv.ID, Err: err}
		}
	}

	dir := filepath.Join(p.WorkDir, "ping-"+randHex(4))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		failAll(err)
		return
	}
	defer os.RemoveAll(dir)

	var procs []*Process
	defer func() { stopAll(procs) }()
	startCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	launch := func(k Kind, args []string, port int) error {
		pr, err := startProcess(k, p.Binaries.Path(k), args, dir, quietLog)
		if err != nil {
			return err
		}
		procs = append(procs, pr)
		return pr.waitListening(startCtx, fmt.Sprintf("127.0.0.1:%d", port))
	}

	// Backends: one Xray and one mihomo for all their servers.
	for _, k := range []Kind{Xray, Mihomo} {
		group := byCore[k]
		if len(group) == 0 {
			continue
		}
		srvs, ports := make([]*model.Server, len(group)), make([]int, len(group))
		for i, e := range group {
			port, err := freePort()
			if err != nil {
				failAll(err)
				return
			}
			srvs[i], ports[i], e.backend = e.srv, port, port
		}
		var (
			cfg  []byte
			err  error
			file string
			args []string
		)
		if k == Xray {
			file = filepath.Join(dir, "xray.json")
			cfg, err = xrayMultiConfig(srvs, ports, "error")
			args = []string{"run", "-c", file}
		} else {
			file = filepath.Join(dir, "mihomo.yaml")
			cfg, err = mihomoMultiConfig(srvs, ports, "error")
			args = []string{"-d", dir, "-f", file}
		}
		if err == nil {
			err = writeSecret(file, cfg)
		}
		if err == nil {
			err = launch(k, args, ports[len(ports)-1])
		}
		if err != nil {
			failAll(fmt.Errorf("start %s for testing: %w", k, err))
			return
		}
	}

	// The sing-box front: inbound in-i is routed to outbound s-i.
	var inbounds, outbounds, endpoints, rules []any
	var measured []*entry
	for i, e := range entries {
		var ob map[string]any
		var err error
		if e.kind == SingBox {
			if ob, err = singBoxOutbound(e.srv); err != nil {
				out <- PingResult{ServerID: e.srv.ID, Err: err}
				continue
			}
		} else {
			ob = map[string]any{"type": "socks", "server": "127.0.0.1", "server_port": e.backend, "version": "5"}
		}
		if e.port, err = freePort(); err != nil {
			out <- PingResult{ServerID: e.srv.ID, Err: err}
			continue
		}
		in, tag := fmt.Sprintf("in-%d", i), fmt.Sprintf("s-%d", i)
		ob["tag"] = tag
		if ob["type"] == "wireguard" {
			endpoints = append(endpoints, ob)
		} else {
			outbounds = append(outbounds, ob)
		}
		inbounds = append(inbounds, map[string]any{"type": "mixed", "tag": in, "listen": "127.0.0.1", "listen_port": e.port})
		rules = append(rules, map[string]any{"inbound": []string{in}, "outbound": tag})
		measured = append(measured, e)
	}
	if len(measured) == 0 {
		return
	}
	cfg := map[string]any{
		"log":       map[string]any{"level": "error"},
		"dns":       map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "local"}}},
		"inbounds":  inbounds,
		"outbounds": append(outbounds, map[string]any{"type": "direct", "tag": "direct"}),
		"route":     map[string]any{"rules": rules, "final": "direct", "default_domain_resolver": "local"},
	}
	if len(endpoints) > 0 {
		cfg["endpoints"] = endpoints
	}
	raw, _ := json.Marshal(cfg)
	file := filepath.Join(dir, "sing-box.json")
	fail := func(err error) {
		for _, e := range measured {
			out <- PingResult{ServerID: e.srv.ID, Err: err}
		}
	}
	if err := writeSecret(file, raw); err != nil {
		fail(err)
		return
	}
	if err := launch(SingBox, []string{"run", "-c", file, "-D", dir, "--disable-color"}, measured[len(measured)-1].port); err != nil {
		fail(fmt.Errorf("start sing-box for testing: %w", err))
		return
	}

	ports := map[string]int{}
	list := make([]model.Server, len(measured))
	for i, e := range measured {
		ports[e.srv.ID] = e.port
		list[i] = *e.srv
	}
	parallel(ctx, list, o.Parallel, out, func(s *model.Server) (time.Duration, error) {
		return httpGetVia(ctx, ports[s.ID], o.URL, o.Timeout)
	})
}

// httpGetVia GETs target through the local proxy on port over a fresh
// connection and returns the time until response headers arrive.
func httpGetVia(ctx context.Context, port int, target string, timeout time.Duration) (time.Duration, error) {
	proxy := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", port)}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true},
		Timeout:   timeout,
		// A redirect still proves the tunnel works; don't follow it.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			if ue.Timeout() {
				return 0, errors.New("timeout")
			}
			err = ue.Err
		}
		return 0, err
	}
	lat := elapsed(start)
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return lat, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// elapsed is time.Since(start), but never zero for a completed measurement:
// Go's monotonic clock on Windows ticks coarsely, so loopback round trips
// can measure as 0, and 0 means "no response" in latency results.
func elapsed(start time.Time) time.Duration {
	return max(time.Since(start), time.Microsecond)
}
