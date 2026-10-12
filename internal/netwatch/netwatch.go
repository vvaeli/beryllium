// Package netwatch reports what network the machine is on and when that
// changes, and tells whether the internet is reachable outside the tunnel.
// It feeds the watchdog (ROADMAP 7B, 7C).
package netwatch

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// Network is the default-route interface with its gateway and addresses.
// The zero value means no usable network.
type Network struct {
	Iface   string
	Index   int
	Gateway netip.Addr
	Addrs   []netip.Addr
}

// Up reports whether there is a default route.
func (n Network) Up() bool { return n.Index != 0 }

// Key identifies the network for change detection.
func (n Network) Key() string {
	if !n.Up() {
		return ""
	}
	parts := []string{n.Iface, n.Gateway.String()}
	for _, a := range n.Addrs {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, " ")
}

func (n Network) String() string {
	if !n.Up() {
		return "none"
	}
	return n.Key()
}

// errNoRoute means there is no default route.
var errNoRoute = errors.New("no default route")

// Current returns the network behind the default route, skipping
// interfaces that hold an address in exclude (the TUN, whose routes must
// not count as a network change).
func Current(exclude []netip.Prefix) (Network, error) {
	routes, err := defaultRoutes()
	if err != nil {
		return Network{}, err
	}
	for _, r := range routes {
		ifc, err := net.InterfaceByIndex(r.Index)
		if err != nil || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		n := Network{Iface: ifc.Name, Index: ifc.Index, Gateway: r.Gateway}
		addrs, _ := ifc.Addrs()
		excluded := false
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if slices.ContainsFunc(exclude, func(p netip.Prefix) bool { return p.Contains(ip) }) {
				excluded = true
				break
			}
			// Link-local and temporary addresses change without the
			// network changing.
			if ip.IsLinkLocalUnicast() || ip.IsLoopback() {
				continue
			}
			n.Addrs = append(n.Addrs, ip)
		}
		if excluded {
			continue
		}
		slices.SortFunc(n.Addrs, netip.Addr.Compare)
		return n, nil
	}
	return Network{}, errNoRoute
}

// defRoute is a default route.
type defRoute struct {
	Index   int
	Gateway netip.Addr
	Metric  int
}

// Events are called by Run. Sleep runs synchronously and must return
// quickly: the OS waits for it before sleeping.
type Events struct {
	Sleep     func()
	Wake      func(source string)
	NetChange func(old, cur Network)
}

// Debounce is how long Run waits for more network events before comparing
// networks (ROADMAP 7.15).
var Debounce = 1500 * time.Millisecond

const (
	pollInterval  = 10 * time.Second
	clockInterval = 5 * time.Second
	// A wall-clock gap this much bigger than the monotonic one means the
	// machine slept: monotonic clocks stop during sleep.
	clockJump = 15 * time.Second
)

// Run watches power and network events until ctx is done. Native sources
// are used where available; network polling and a clock-jump detector
// catch whatever they miss (DarkWake, missed notifications).
func Run(ctx context.Context, log *slog.Logger, exclude []netip.Prefix, ev Events) {
	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Go(func() {
		if err := watchPower(ctx, log, ev.Sleep, func() { ev.Wake("os") }); err != nil && ctx.Err() == nil {
			log.Info("no sleep/wake notifications; relying on clock jumps", "err", err)
		}
	})

	kick := make(chan struct{}, 1)
	wg.Go(func() {
		if err := watchNetwork(ctx, kick); err != nil && ctx.Err() == nil {
			log.Info("no network change notifications; polling", "err", err)
		}
	})

	last, _ := Current(exclude)
	poll := time.NewTicker(pollInterval)
	defer poll.Stop()
	clock := time.NewTicker(clockInterval)
	defer clock.Stop()
	prev := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-clock.C:
			if jumped(now.Sub(prev), now.Round(0).Sub(prev.Round(0))) {
				log.Info("clock jump: the machine was asleep")
				ev.Wake("clock")
			}
			prev = now
			continue
		case <-poll.C:
		case <-kick:
			if !debounce(ctx, kick) {
				return
			}
		}
		cur, _ := Current(exclude)
		if cur.Key() != last.Key() {
			log.Info("network changed", "from", last.String(), "to", cur.String())
			old := last
			last = cur
			ev.NetChange(old, cur)
		}
	}
}

// jumped reports whether wall time advanced much more than monotonic time
// (Round(0) strips the monotonic reading from a time.Time).
func jumped(mono, wall time.Duration) bool {
	return wall-mono > clockJump
}

// debounce waits until kicks stop for Debounce.
func debounce(ctx context.Context, kick <-chan struct{}) bool {
	t := time.NewTimer(Debounce)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-kick:
			t.Reset(Debounce)
		case <-t.C:
			return true
		}
	}
}

// notify sends a non-blocking kick.
func notify(kick chan<- struct{}) {
	select {
	case kick <- struct{}{}:
	default:
	}
}
