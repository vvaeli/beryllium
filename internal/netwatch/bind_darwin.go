package netwatch

import (
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func bindControl(n Network) func(network, address string, c syscall.RawConn) error {
	return func(network, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, n.Index)
			} else {
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, n.Index)
			}
		})
	}
}
