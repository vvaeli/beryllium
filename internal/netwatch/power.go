//go:build linux || windows || (darwin && cgo)

package netwatch

import "time"

// SleepBudget bounds the sleep handler: the OS is waiting for us.
const SleepBudget = 5 * time.Second

// runBounded runs f, returning after SleepBudget even if f doesn't.
func runBounded(f func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(SleepBudget):
	}
}
