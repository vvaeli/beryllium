package netwatch

import (
	"context"
	"net"
	"net/http"
	"time"
)

// Reach is what a direct connectivity check found.
type Reach int

// Reach results.
const (
	Offline Reach = iota
	Online
	// Captive means HTTP works but answers with something else: a Wi-Fi
	// login page (ROADMAP 7.16).
	Captive
)

func (r Reach) String() string {
	switch r {
	case Online:
		return "online"
	case Captive:
		return "captive portal"
	}
	return "offline"
}

// CheckURLs answer 204 to plain HTTP when the internet is reachable.
var CheckURLs = []string{
	"http://connectivitycheck.gstatic.com/generate_204",
	"http://cp.cloudflare.com/generate_204",
}

// Check probes CheckURLs directly, bypassing the tunnel: sockets are bound
// to n's interface (as sing-box does with auto_detect_interface) and DNS
// goes to the system resolvers over the same interface.
func Check(ctx context.Context, n Network) Reach {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	d := Dialer(n)
	resolver := &net.Resolver{PreferGo: true, Dial: d.DialContext}
	tr := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := resolver.LookupNetIP(ctx, "ip4", host)
			if err != nil || len(ips) == 0 {
				// IPv6-only networks, or a resolver we can't reach bound.
				return d.DialContext(ctx, network, addr)
			}
			return d.DialContext(ctx, "tcp4", net.JoinHostPort(ips[0].String(), port))
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	results := make(chan Reach, len(CheckURLs))
	for _, u := range CheckURLs {
		go func() {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			resp, err := client.Do(req)
			if err != nil {
				results <- Offline
				return
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusNoContent {
				results <- Online
			} else {
				results <- Captive
			}
		}()
	}
	best := Offline
	for range CheckURLs {
		switch r := <-results; r {
		case Online:
			return Online
		case Captive:
			best = Captive
		}
	}
	return best
}

// Dialer returns a dialer whose sockets leave through n's interface, so
// they bypass a TUN that captures the default route. Binding errors are
// ignored (e.g. no privileges outside TUN mode, where it isn't needed).
func Dialer(n Network) *net.Dialer {
	d := &net.Dialer{Timeout: 3 * time.Second}
	if n.Up() {
		d.Control = bindControl(n)
	}
	return d
}
