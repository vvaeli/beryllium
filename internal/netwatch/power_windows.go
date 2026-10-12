package netwatch

import (
	"context"
	"log/slog"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	deviceNotifyCallback = 2

	pbtAPMSuspend         = 0x4
	pbtAPMResumeAutomatic = 0x12 // sent on every resume
)

type deviceNotifySubscribeParameters struct {
	callback uintptr
	context  uintptr
}

var (
	procPowerRegisterSuspendResumeNotification = windows.NewLazySystemDLL("powrprof.dll").
							NewProc("PowerRegisterSuspendResumeNotification")

	powerSubs  registry[powerHandlers]
	powerStart sync.Once
	powerErr   error

	powerCallback = windows.NewCallback(func(_, typ, _ uintptr) uintptr {
		switch typ {
		case pbtAPMSuspend:
			dispatchPower(&powerSubs, true)
		case pbtAPMResumeAutomatic:
			dispatchPower(&powerSubs, false)
		}
		return 0
	})

	// Windows keeps a pointer to the parameters while registered.
	powerParams = &deviceNotifySubscribeParameters{callback: powerCallback}
)

// watchPower registers once per process for suspend/resume callbacks,
// which work in a service without a window (ROADMAP 7.9).
func watchPower(ctx context.Context, _ *slog.Logger, sleep, wake func()) error {
	powerStart.Do(func() {
		if powerErr = procPowerRegisterSuspendResumeNotification.Find(); powerErr != nil {
			return
		}
		var h uintptr
		r, _, _ := procPowerRegisterSuspendResumeNotification.Call(deviceNotifyCallback,
			uintptr(unsafe.Pointer(powerParams)), uintptr(unsafe.Pointer(&h)))
		if r != 0 {
			powerErr = windows.Errno(r)
		}
	})
	if powerErr != nil {
		return powerErr
	}
	remove := powerSubs.add(powerHandlers{sleep, wake})
	defer remove()
	<-ctx.Done()
	return nil
}
