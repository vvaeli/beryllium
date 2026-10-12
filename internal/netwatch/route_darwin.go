package netwatch

import (
	"net/netip"
	"slices"
	"syscall"

	"golang.org/x/net/route"
)

// defaultRoutes reads the unscoped default routes from the kernel. sing-box
// captures traffic with narrower routes, so the default route stays on the
// physical interface.
func defaultRoutes() ([]defRoute, error) {
	var out []defRoute
	for _, af := range []int{syscall.AF_INET, syscall.AF_INET6} {
		rib, err := route.FetchRIB(af, route.RIBTypeRoute, 0)
		if err != nil {
			return nil, err
		}
		msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			rm, ok := m.(*route.RouteMessage)
			if !ok || rm.Flags&syscall.RTF_UP == 0 || rm.Flags&syscall.RTF_GATEWAY == 0 || rm.Flags&rtfIfScope != 0 {
				continue
			}
			if len(rm.Addrs) <= syscall.RTAX_NETMASK || !isZero(rm.Addrs[syscall.RTAX_DST]) {
				continue
			}
			if mask := rm.Addrs[syscall.RTAX_NETMASK]; mask != nil && !isZero(mask) {
				continue
			}
			r := defRoute{Index: rm.Index}
			switch g := rm.Addrs[syscall.RTAX_GATEWAY].(type) {
			case *route.Inet4Addr:
				r.Gateway = netip.AddrFrom4(g.IP)
			case *route.Inet6Addr:
				r.Gateway = netip.AddrFrom16(g.IP)
			}
			if af == syscall.AF_INET6 {
				r.Metric = 1 // prefer IPv4
			}
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return nil, errNoRoute
	}
	slices.SortStableFunc(out, func(a, b defRoute) int { return a.Metric - b.Metric })
	return out, nil
}

// rtfIfScope marks per-interface default routes; the unscoped one is the
// primary.
const rtfIfScope = 0x1000000

func isZero(a route.Addr) bool {
	switch a := a.(type) {
	case *route.Inet4Addr:
		return a.IP == [4]byte{}
	case *route.Inet6Addr:
		return a.IP == [16]byte{}
	}
	return false
}
