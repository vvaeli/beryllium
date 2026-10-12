package netwatch

import (
	"encoding/binary"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

const (
	ipUnicastIf   = 31 // IP_UNICAST_IF
	ipv6UnicastIf = 31 // IPV6_UNICAST_IF
)

func bindControl(n Network) func(network, address string, c syscall.RawConn) error {
	return func(network, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			h := windows.Handle(fd)
			if strings.HasSuffix(network, "6") {
				_ = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, ipv6UnicastIf, n.Index)
				return
			}
			// IP_UNICAST_IF takes the index in network byte order.
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(n.Index))
			_ = windows.SetsockoptInt(h, windows.IPPROTO_IP, ipUnicastIf, int(binary.NativeEndian.Uint32(b[:])))
		})
	}
}
