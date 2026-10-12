package netwatch

import (
	"errors"
	"net/netip"
	"slices"
	"unsafe"

	"golang.org/x/sys/windows"
)

// defaultRoutes lists adapters that are up and have a gateway. The wintun
// adapter has none, and Current skips it by address anyway.
func defaultRoutes() ([]defRoute, error) {
	size := uint32(16 << 10)
	var buf []byte
	for {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_GATEWAYS|windows.GAA_FLAG_SKIP_ANYCAST|
			windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return nil, err
		}
	}
	var out []defRoute
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		if a.OperStatus != windows.IfOperStatusUp || a.FirstGatewayAddress == nil {
			continue
		}
		r := defRoute{Index: int(a.IfIndex), Metric: int(a.Ipv4Metric)}
		if r.Index == 0 {
			r.Index = int(a.Ipv6IfIndex)
		}
		if ip := a.FirstGatewayAddress.Address.IP(); ip != nil {
			if addr, ok := netip.AddrFromSlice(ip); ok {
				r.Gateway = addr.Unmap()
			}
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, errNoRoute
	}
	slices.SortStableFunc(out, func(a, b defRoute) int { return a.Metric - b.Metric })
	return out, nil
}
