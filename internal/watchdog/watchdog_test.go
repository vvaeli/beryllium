package watchdog

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	c.advance(d)
	return ctx.Err()
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// fakeTarget is a tunnel that is broken until one of fixedBy runs.
type fakeTarget struct {
	clock     *fakeClock
	active    bool
	broken    bool
	fixedBy   []Step
	skip      []Step
	reach     []Reach // consumed per Reach call; the last one repeats
	steps     []Step
	probes    int
	wakes     int
	onRecover func(Step)
}

func (f *fakeTarget) Active() bool { return f.active }

func (f *fakeTarget) Probe(context.Context) error {
	f.probes++
	f.clock.advance(100 * time.Millisecond)
	if f.broken {
		return errors.New("timeout")
	}
	return nil
}

func (f *fakeTarget) Reach(context.Context) Reach {
	r := f.reach[0]
	if len(f.reach) > 1 {
		f.reach = f.reach[1:]
	}
	return r
}

func (f *fakeTarget) Recover(_ context.Context, s Step) (string, error) {
	if slices.Contains(f.skip, s) {
		return "", ErrSkip
	}
	f.steps = append(f.steps, s)
	if f.onRecover != nil {
		f.onRecover(s)
	}
	if slices.Contains(f.fixedBy, s) {
		f.broken = false
	}
	return s.String(), nil
}

func (f *fakeTarget) AfterWake(context.Context) { f.wakes++ }

func newTest(t *testing.T) (*Watchdog, *fakeTarget, *fakeClock) {
	t.Helper()
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	ft := &fakeTarget{clock: clock, active: true, reach: []Reach{Online}}
	w := New(ft, func() Config { return Config{} }, clock, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w.Begin()
	return w, ft, clock
}

func TestHealthyStaysConnected(t *testing.T) {
	w, ft, _ := newTest(t)
	for range 5 {
		w.handle(t.Context(), TriggerWatchdog)
	}
	if st := w.Status(); st.State != Connected || st.Count != 0 || ft.probes != 5 || len(ft.steps) != 0 {
		t.Fatalf("status %+v, probes %d, steps %v", st, ft.probes, ft.steps)
	}
}

func TestThresholdThenLadder(t *testing.T) {
	w, ft, _ := newTest(t)
	ft.broken, ft.fixedBy = true, []Step{StepRestartCore}

	w.handle(t.Context(), TriggerWatchdog)
	w.handle(t.Context(), TriggerWatchdog)
	if st := w.Status(); st.State != Degraded || st.Problem != ProblemChecksFailing || len(ft.steps) != 0 {
		t.Fatalf("after 2 failures: %+v, steps %v", st, ft.steps)
	}
	if d := w.nextDelay(); d != 5*time.Second {
		t.Fatalf("degraded retry delay = %v", d)
	}
	w.handle(t.Context(), TriggerWatchdog)
	st := w.Status()
	if st.State != Connected || st.Count != 1 || st.LastTrigger != TriggerWatchdog || st.LastResult != "restart core" {
		t.Fatalf("after recovery: %+v", st)
	}
	if want := []Step{StepResetConnections, StepRestartCore}; !slices.Equal(ft.steps, want) {
		t.Fatalf("steps %v, want %v", ft.steps, want)
	}
	if d := w.nextDelay(); d != 30*time.Second {
		t.Fatalf("healthy delay = %v", d)
	}
}

func TestSkippedSteps(t *testing.T) {
	w, ft, _ := newTest(t)
	ft.broken, ft.fixedBy, ft.skip = true, []Step{StepSwitchCore}, []Step{StepSwitchServer}
	for range 3 {
		w.handle(t.Context(), TriggerWatchdog)
	}
	if want := []Step{StepResetConnections, StepRestartCore, StepSwitchCore}; !slices.Equal(ft.steps, want) {
		t.Fatalf("steps %v, want %v", ft.steps, want)
	}
	if st := w.Status(); st.State != Connected || st.LastResult != "switch core" {
		t.Fatalf("status %+v", st)
	}
}

func TestOfflineDoesNotEscalate(t *testing.T) {
	for _, tc := range []struct {
		reach   Reach
		problem Problem
	}{{Offline, ProblemOffline}, {Captive, ProblemCaptive}} {
		w, ft, _ := newTest(t)
		ft.broken, ft.reach = true, []Reach{tc.reach}
		for range 10 {
			w.handle(t.Context(), TriggerWatchdog)
		}
		if st := w.Status(); st.State != Degraded || st.Problem != tc.problem || len(ft.steps) != 0 {
			t.Fatalf("%v: status %+v, steps %v", tc.reach, st, ft.steps)
		}
		// The network returns and the tunnel is fine again.
		ft.broken, ft.reach = false, []Reach{Online}
		w.handle(t.Context(), TriggerWatchdog)
		if st := w.Status(); st.State != Connected || st.Problem != ProblemNone {
			t.Fatalf("%v: after the network returned: %+v", tc.reach, st)
		}
	}
}

func TestExhaustedBacksOff(t *testing.T) {
	w, ft, _ := newTest(t)
	ft.broken = true
	for range 3 {
		w.handle(t.Context(), TriggerWatchdog)
	}
	st := w.Status()
	if st.State != Failed || st.Problem != ProblemExhausted || st.Count != 1 {
		t.Fatalf("status %+v", st)
	}
	if !slices.Equal(ft.steps, Ladder) {
		t.Fatalf("steps %v", ft.steps)
	}
	if d := w.nextDelay(); d != 30*time.Second {
		t.Fatalf("first backoff %v", d)
	}
	// Every failed check in the failed state retries the ladder with a
	// doubled backoff.
	w.handle(t.Context(), TriggerWatchdog)
	w.handle(t.Context(), TriggerWatchdog)
	if d := w.nextDelay(); d != 2*time.Minute {
		t.Fatalf("third backoff %v", d)
	}
	for range 10 {
		w.handle(t.Context(), TriggerWatchdog)
	}
	if d := w.nextDelay(); d != 10*time.Minute {
		t.Fatalf("max backoff %v", d)
	}
	ft.broken = false
	w.handle(t.Context(), TriggerWatchdog)
	if st := w.Status(); st.State != Connected || w.nextDelay() != 30*time.Second {
		t.Fatalf("after the server came back: %+v", st)
	}
}

func TestWakeWaitsForNetwork(t *testing.T) {
	w, ft, clock := newTest(t)
	ft.broken, ft.fixedBy = true, []Step{StepResetConnections}
	ft.reach = []Reach{Offline, Offline, Offline, Online}
	start := clock.Now()
	w.handle(t.Context(), TriggerWake)
	st := w.Status()
	if st.State != Connected || st.Count != 1 || st.LastTrigger != TriggerWake || st.LastResult != "reset connections" {
		t.Fatalf("status %+v", st)
	}
	if ft.wakes != 1 || !slices.Equal(ft.steps, []Step{StepResetConnections}) {
		t.Fatalf("wakes %d, steps %v", ft.wakes, ft.steps)
	}
	// Three 1s polls for the network plus the probe.
	if st.LastDuration < 3*time.Second || st.LastDuration > 4*time.Second || clock.Now().Sub(start) != st.LastDuration {
		t.Fatalf("duration %v", st.LastDuration)
	}
}

func TestWakeWithoutNetwork(t *testing.T) {
	w, ft, clock := newTest(t)
	ft.reach = []Reach{Offline}
	start := clock.Now()
	w.handle(t.Context(), TriggerWake)
	if st := w.Status(); st.State != Degraded || st.Problem != ProblemOffline || len(ft.steps) != 0 || ft.wakes != 0 {
		t.Fatalf("status %+v, steps %v", st, ft.steps)
	}
	if waited := clock.Now().Sub(start); waited != 30*time.Second {
		t.Fatalf("waited %v for the network", waited)
	}
}

func TestWakeEscalates(t *testing.T) {
	w, ft, _ := newTest(t)
	ft.broken, ft.fixedBy = true, []Step{StepSwitchServer}
	w.handle(t.Context(), TriggerNetChange)
	want := []Step{StepResetConnections, StepRestartCore, StepSwitchServer}
	if st := w.Status(); st.State != Connected || st.LastTrigger != TriggerNetChange || !slices.Equal(ft.steps, want) {
		t.Fatalf("status %+v, steps %v", st, ft.steps)
	}
}

func TestDuplicateWake(t *testing.T) {
	w, ft, clock := newTest(t)
	w.handle(t.Context(), TriggerWake)
	w.handle(t.Context(), TriggerWake) // the clock-jump detector, same wake
	if ft.wakes != 1 {
		t.Fatalf("wakes %d", ft.wakes)
	}
	clock.advance(time.Minute)
	w.handle(t.Context(), TriggerWake)
	if ft.wakes != 2 {
		t.Fatalf("wakes %d", ft.wakes)
	}
	// A quick sleep and wake again is a new wake.
	w.Sleep(t.Context())
	w.handle(t.Context(), TriggerWake)
	if ft.wakes != 3 {
		t.Fatalf("wakes %d", ft.wakes)
	}
}

func TestSleepPausesChecks(t *testing.T) {
	w, ft, clock := newTest(t)
	w.Sleep(t.Context())
	if !slices.Equal(ft.steps, []Step{StepResetConnections}) {
		t.Fatalf("steps %v", ft.steps)
	}
	ft.broken = true
	w.handle(t.Context(), TriggerWatchdog)
	if ft.probes != 0 {
		t.Fatal("checked while asleep")
	}
	// No wake came (sleep cancelled): checks resume on their own.
	clock.advance(2 * time.Minute)
	w.handle(t.Context(), TriggerWatchdog)
	if ft.probes != 1 {
		t.Fatalf("probes %d", ft.probes)
	}
}

func TestDisconnectDuringRecovery(t *testing.T) {
	w, ft, _ := newTest(t)
	ft.broken = true
	ft.onRecover = func(s Step) {
		if s == StepRestartCore {
			w.End() // the user disconnected
			ft.active = false
		}
	}
	for range 3 {
		w.handle(t.Context(), TriggerWatchdog)
	}
	if st := w.Status(); st.State != Idle || st.Count != 0 {
		t.Fatalf("status %+v", st)
	}
	if want := []Step{StepResetConnections, StepRestartCore}; !slices.Equal(ft.steps, want) {
		t.Fatalf("steps %v, want %v", ft.steps, want)
	}
}

func TestInactiveIgnored(t *testing.T) {
	w, ft, _ := newTest(t)
	ft.active = false
	w.handle(t.Context(), TriggerWatchdog)
	w.handle(t.Context(), TriggerWake)
	if ft.probes != 0 || ft.wakes != 0 {
		t.Fatal("acted without a connection")
	}
}

func TestRunHandlesTriggers(t *testing.T) {
	w, ft, _ := newTest(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()
	w.Trigger(ctx, TriggerNetChange, true)
	if ft.wakes != 1 {
		t.Fatalf("wakes %d", ft.wakes)
	}
	cancel()
	<-done
}
