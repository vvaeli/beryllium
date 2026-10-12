//go:build (darwin && cgo) || windows

package netwatch

import "sync"

// registry fans OS callbacks, which are registered once per process, out
// to every watcher (tests run several daemons in one process).
type registry[T any] struct {
	mu   sync.Mutex
	next int
	m    map[int]T
}

func (r *registry[T]) add(v T) (remove func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = map[int]T{}
	}
	r.next++
	id := r.next
	r.m[id] = v
	return func() {
		r.mu.Lock()
		delete(r.m, id)
		r.mu.Unlock()
	}
}

func (r *registry[T]) all() []T {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]T, 0, len(r.m))
	for _, v := range r.m {
		out = append(out, v)
	}
	return out
}

type powerHandlers struct{ sleep, wake func() }

// dispatchPower runs sleep handlers (bounded, the OS waits) or wake
// handlers (in the background).
func dispatchPower(r *registry[powerHandlers], sleeping bool) {
	for _, h := range r.all() {
		if sleeping {
			runBounded(h.sleep)
		} else {
			go h.wake()
		}
	}
}
