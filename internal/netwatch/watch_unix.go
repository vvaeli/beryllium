//go:build linux || darwin

package netwatch

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"
)

// readKicks reads messages from a routing socket until ctx is done; any
// message is a kick, Run compares networks itself.
func readKicks(ctx context.Context, fd int, kick chan<- struct{}) error {
	go func() {
		<-ctx.Done()
		unix.Close(fd) // unblocks Read
	}()
	buf := make([]byte, 64<<10)
	for {
		if _, err := unix.Read(fd, buf); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.ENOBUFS) {
				notify(kick) // dropped messages: something changed
				continue
			}
			return err
		}
		notify(kick)
	}
}
