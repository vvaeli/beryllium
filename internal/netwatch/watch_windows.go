package netwatch

import (
	"context"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	netSubs  registry[chan<- struct{}]
	netStart sync.Once
	netErr   error

	changeCallback = windows.NewCallback(func(_, _, _ uintptr) uintptr {
		for _, k := range netSubs.all() {
			notify(k)
		}
		return 0
	})
)

// watchNetwork kicks on interface, address and route changes (ROADMAP
// 7.14). Notifications are registered once per process.
func watchNetwork(ctx context.Context, kick chan<- struct{}) error {
	netStart.Do(func() {
		register := []func(uint16, uintptr, unsafe.Pointer, bool, *windows.Handle) error{
			windows.NotifyIpInterfaceChange, windows.NotifyUnicastIpAddressChange, windows.NotifyRouteChange2,
		}
		for _, reg := range register {
			var h windows.Handle
			if err := reg(windows.AF_UNSPEC, changeCallback, nil, false, &h); err != nil {
				netErr = err
				return
			}
		}
	})
	if netErr != nil {
		return netErr
	}
	remove := netSubs.add(kick)
	defer remove()
	<-ctx.Done()
	return nil
}
