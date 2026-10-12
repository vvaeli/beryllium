package netwatch

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func bindControl(n Network) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			_ = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, n.Iface)
		})
	}
}
