//go:build cgo

package netwatch

/*
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation
int berylPowerRun(void);
*/
import "C"

import (
	"context"
	"errors"
	"log/slog"
	"runtime"
	"sync"
)

var (
	powerSubs  registry[powerHandlers]
	powerStart sync.Once
	powerErr   = make(chan error, 1)
)

//export goPowerEvent
func goPowerEvent(kind C.int) {
	dispatchPower(&powerSubs, kind == 1)
}

// watchPower listens to IOKit power notifications (ROADMAP 7.6). The run
// loop is started once per process and never stopped. DarkWake also
// reports HasPoweredOn; the watchdog keeps that cheap (7.7).
func watchPower(ctx context.Context, _ *slog.Logger, sleep, wake func()) error {
	powerStart.Do(func() {
		go func() {
			// The run loop belongs to this thread.
			runtime.LockOSThread()
			if C.berylPowerRun() != 0 {
				powerErr <- errors.New("IORegisterForSystemPower failed")
			}
		}()
	})
	remove := powerSubs.add(powerHandlers{sleep, wake})
	defer remove()
	select {
	case <-ctx.Done():
		return nil
	case err := <-powerErr:
		powerErr <- err // for later watchers
		return err
	}
}
