package netwatch

import (
	"context"

	"golang.org/x/sys/unix"
)

// watchNetwork kicks on routing socket messages (interface, address and
// route changes; ROADMAP 7.12).
func watchNetwork(ctx context.Context, kick chan<- struct{}) error {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	return readKicks(ctx, fd, kick)
}
