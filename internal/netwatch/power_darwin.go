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
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
)

var (
	powerLog   atomic.Pointer[slog.Logger]
	powerSubs  registry[powerHandlers]
	powerStart sync.Once
	powerErr   = make(chan error, 1)
)

// powerMessages names IOKit messages (IOMessage.h).
var powerMessages = map[uint32]string{
	0xe0000270: "can system sleep",
	0xe0000280: "system will sleep",
	0xe0000290: "system will not sleep",
	0xe0000300: "system has powered on",
	0xe0000320: "system will power on",
}

//export goPowerMessage
func goPowerMessage(t C.uint) {
	if log := powerLog.Load(); log != nil {
		name, ok := powerMessages[uint32(t)]
		if !ok {
			name = fmt.Sprintf("%#x", uint32(t))
		}
		log.Info("power notification", "message", name)
	}
}

//export goPowerEvent
func goPowerEvent(kind C.int) {
	dispatchPower(&powerSubs, kind == 1)
}

// watchPower listens to IOKit power notifications (ROADMAP 7.6). The run
// loop is started once per process and never stopped. DarkWake also
// reports HasPoweredOn; the watchdog keeps that cheap (7.7).
func watchPower(ctx context.Context, log *slog.Logger, sleep, wake func()) error {
	powerLog.CompareAndSwap(nil, log)
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
