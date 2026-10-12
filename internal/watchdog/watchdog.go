// Package watchdog keeps a connection alive: it health-checks the tunnel,
// reacts to sleep, wake and network changes, and walks a recovery ladder
// when the tunnel is broken (ROADMAP phase 7).
package watchdog

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// State of the supervised connection.
type State int

// States. Idle means there is no connection to supervise.
const (
	Idle State = iota
	Connected
	// Degraded: checks fail but recovery hasn't started, or the network
	// itself is down (nothing to recover until it returns).
	Degraded
	Recovering
	// Failed: the ladder is exhausted; checks continue with backoff.
	Failed
)

func (s State) String() string {
	return [...]string{"idle", "connected", "degraded", "recovering", "failed"}[s]
}

// Trigger is what started a recovery.
type Trigger int

// Triggers.
const (
	TriggerNone Trigger = iota
	TriggerWatchdog
	TriggerWake
	TriggerNetChange
)

func (t Trigger) String() string {
	return [...]string{"none", "watchdog", "wake", "network change"}[t]
}

// Reach is the state of the network outside the tunnel.
type Reach int

// Reach values.
const (
	Offline Reach = iota
	Online
	Captive
)

// Step is one rung of the recovery ladder (ROADMAP 7.4).
type Step int

// Steps, cheapest first.
const (
	StepResetConnections Step = iota
	StepRestartCore
	StepSwitchServer
	StepSwitchCore
)

func (s Step) String() string {
	return [...]string{"reset connections", "restart core", "switch server", "switch core"}[s]
}

// Ladder is the order recovery tries steps in.
var Ladder = []Step{StepResetConnections, StepRestartCore, StepSwitchServer, StepSwitchCore}

// ErrSkip from Target.Recover means the step doesn't apply (e.g. only one
// server or one capable core).
var ErrSkip = errors.New("step not applicable")

// Target is the connection being supervised.
type Target interface {
	// Active reports whether a connection is up (or being restarted).
	Active() bool
	// Probe checks the tunnel itself, e.g. generate_204 through the proxy.
	Probe(ctx context.Context) error
	// Reach checks the network directly, outside the tunnel.
	Reach(ctx context.Context) Reach
	// Recover performs a step and returns a description of what it did.
	Recover(ctx context.Context, s Step) (string, error)
	// AfterWake runs once the network is ready after sleep or a network
	// change: flush DNS caches and the like.
	AfterWake(ctx context.Context)
}

// Clock is time for the watchdog; tests use a fake one.
type Clock interface {
	Now() time.Time
	// Sleep waits d or until ctx is done.
	Sleep(ctx context.Context, d time.Duration) error
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Config tunes the watchdog; zero fields take defaults.
type Config struct {
	// Interval between checks while healthy (default 30s).
	Interval time.Duration
	// Threshold of consecutive failed checks before recovery (default 3).
	Threshold int
	// RetryInterval between checks while degraded (default 5s), so a
	// broken tunnel is noticed in seconds, not minutes.
	RetryInterval time.Duration
	// ReadyTimeout is how long to wait for the network after wake
	// (default 30s; ROADMAP 7.10).
	ReadyTimeout time.Duration
	// ProbeTimeout bounds one probe (default 10s).
	ProbeTimeout time.Duration
	// MinBackoff and MaxBackoff bound checks in the failed state
	// (default 30s and 10m; ROADMAP 7.5).
	MinBackoff, MaxBackoff time.Duration
	// SettleTime is how long after a recovery step to wait before the
	// probe (default 1s), so a restarted core has its connections up.
	SettleTime time.Duration
}

func (c Config) withDefaults() Config {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&c.Interval, 30*time.Second)
	def(&c.RetryInterval, 5*time.Second)
	def(&c.ReadyTimeout, 30*time.Second)
	def(&c.ProbeTimeout, 10*time.Second)
	def(&c.MinBackoff, 30*time.Second)
	def(&c.MaxBackoff, 10*time.Minute)
	def(&c.SettleTime, time.Second)
	if c.Threshold <= 0 {
		c.Threshold = 3
	}
	return c
}

// Problem explains a non-connected state.
type Problem int

// Problems.
const (
	ProblemNone Problem = iota
	ProblemChecksFailing
	ProblemOffline
	ProblemCaptive
	ProblemExhausted
)

// Status is a snapshot for the API (ROADMAP 7.21).
type Status struct {
	State   State
	Problem Problem
	// Detail is a human-readable reason for Problem.
	Detail string
	// Recovery metrics since the connection started.
	Count        int
	LastTrigger  Trigger
	LastAt       time.Time
	LastDuration time.Duration
	LastResult   string
}

type event struct {
	trigger Trigger
	done    chan struct{}
}

// Watchdog supervises one connection at a time; see Begin and End.
type Watchdog struct {
	t     Target
	clock Clock
	log   *slog.Logger
	cfg   func() Config

	events chan event

	mu       sync.Mutex
	st       Status
	epoch    int
	failures int
	// backoff is the current delay between checks in the failed state.
	backoff time.Duration
	// asleepUntil suppresses checks between a sleep notification and wake.
	asleepUntil time.Time
	lastWake    time.Time
}

// New creates a watchdog; cfg is read before every decision, so settings
// changes apply without a restart. clock may be nil.
func New(t Target, cfg func() Config, clock Clock, log *slog.Logger) *Watchdog {
	if clock == nil {
		clock = realClock{}
	}
	return &Watchdog{t: t, cfg: cfg, clock: clock, log: log, events: make(chan event, 8)}
}

// Status returns the current state and metrics.
func (w *Watchdog) Status() Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.st
}

// Begin starts supervising a new connection and resets the metrics.
func (w *Watchdog) Begin() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.epoch++
	w.st = Status{State: Connected}
	w.failures, w.backoff = 0, 0
}

// Restarted is called when the connection was restarted for another
// reason (settings changed): a recovery in progress is abandoned and the
// state is healthy again; metrics are kept.
func (w *Watchdog) Restarted() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.epoch++
	w.st.State, w.st.Problem, w.st.Detail = Connected, ProblemNone, ""
	w.failures, w.backoff = 0, 0
}

// End stops supervising.
func (w *Watchdog) End() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.epoch++
	w.st = Status{}
	w.failures, w.backoff = 0, 0
}

// Trigger queues an event; wait blocks until it was handled.
func (w *Watchdog) Trigger(ctx context.Context, t Trigger, wait bool) {
	ev := event{trigger: t}
	if wait {
		ev.done = make(chan struct{})
	}
	select {
	case w.events <- ev:
	case <-ctx.Done():
		return
	}
	if wait {
		select {
		case <-ev.done:
		case <-ctx.Done():
		}
	}
}

// Sleep is called when the machine is about to sleep: connections are
// closed so apps don't hold dead sockets after wake, and checks pause.
func (w *Watchdog) Sleep(ctx context.Context) {
	if !w.t.Active() {
		return
	}
	w.mu.Lock()
	// Bounded, in case the sleep was cancelled and no wake follows.
	w.asleepUntil = w.clock.Now().Add(time.Minute)
	w.lastWake = time.Time{} // the next wake is a new one
	w.mu.Unlock()
	w.log.Info("going to sleep: closing tunnel connections")
	if _, err := w.t.Recover(ctx, StepResetConnections); err != nil {
		w.log.Warn("closing connections before sleep failed", "err", err)
	}
}

// Run handles events and periodic checks until ctx is done.
func (w *Watchdog) Run(ctx context.Context) {
	for {
		t := time.NewTimer(w.nextDelay())
		var ev event
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case ev = <-w.events:
			t.Stop()
		case <-t.C:
			ev = event{trigger: TriggerWatchdog}
		}
		w.handle(ctx, ev.trigger)
		if ev.done != nil {
			close(ev.done)
		}
	}
}

// nextDelay is the wait until the next periodic check.
func (w *Watchdog) nextDelay() time.Duration {
	cfg := w.cfg().withDefaults()
	w.mu.Lock()
	defer w.mu.Unlock()
	switch w.st.State {
	case Degraded:
		return cfg.RetryInterval
	case Failed:
		return max(w.backoff, cfg.MinBackoff)
	}
	return cfg.Interval
}

func (w *Watchdog) handle(ctx context.Context, tr Trigger) {
	if !w.t.Active() {
		return
	}
	switch tr {
	case TriggerWatchdog:
		w.check(ctx)
	case TriggerWake, TriggerNetChange:
		w.mu.Lock()
		w.asleepUntil = time.Time{}
		// The OS and the clock-jump detector both report the same wake;
		// Sleep clears lastWake, so only a wake without a sleep in between
		// is a duplicate.
		dup := tr == TriggerWake && !w.lastWake.IsZero() && w.clock.Now().Sub(w.lastWake) < 15*time.Second
		if tr == TriggerWake {
			w.lastWake = w.clock.Now()
		}
		w.mu.Unlock()
		if !dup {
			w.wake(ctx, tr)
		}
	}
}

// check is the periodic health check (ROADMAP 7.1, 7.2).
func (w *Watchdog) check(ctx context.Context) {
	cfg := w.cfg().withDefaults()
	w.mu.Lock()
	asleep := w.clock.Now().Before(w.asleepUntil)
	state, epoch := w.st.State, w.epoch
	w.mu.Unlock()
	if asleep {
		return
	}
	err := w.probe(ctx, cfg)
	if err == nil {
		w.healthy(epoch)
		return
	}
	reach := w.t.Reach(ctx)
	if !w.current(epoch) {
		return
	}
	if reach != Online {
		// Nothing a new server or core could fix; don't burn the ladder.
		w.offline(epoch, reach)
		return
	}
	w.mu.Lock()
	w.failures++
	n := w.failures
	w.mu.Unlock()
	if state == Failed {
		w.log.Info("still failing; retrying recovery", "err", err)
		w.recover(ctx, TriggerWatchdog, epoch)
		return
	}
	if n < cfg.Threshold {
		w.log.Info("health check failed", "failures", n, "threshold", cfg.Threshold, "err", err)
		w.set(epoch, func(s *Status) {
			s.State, s.Problem, s.Detail = Degraded, ProblemChecksFailing, "health check failed: "+err.Error()
		})
		return
	}
	w.log.Warn("health checks keep failing; recovering", "failures", n, "err", err)
	w.recover(ctx, TriggerWatchdog, epoch)
}

// wake handles wake and network changes: wait for the network, then a
// cheap reset and check; the full ladder only if that fails (ROADMAP 7.7,
// 7.10, 7.11, 7.15).
func (w *Watchdog) wake(ctx context.Context, tr Trigger) {
	cfg := w.cfg().withDefaults()
	w.mu.Lock()
	epoch := w.epoch
	w.mu.Unlock()
	start := w.clock.Now()
	w.log.Info("checking the tunnel", "trigger", tr)
	w.set(epoch, func(s *Status) { s.State, s.Problem, s.Detail = Recovering, ProblemNone, "" })

	reach := w.waitReady(ctx, cfg, epoch)
	if !w.current(epoch) {
		return
	}
	if reach != Online {
		w.offline(epoch, reach)
		return
	}
	w.t.AfterWake(ctx)
	did, err := w.t.Recover(ctx, StepResetConnections)
	if err != nil && !errors.Is(err, ErrSkip) {
		w.log.Warn("resetting connections failed", "err", err)
	}
	if err := w.probe(ctx, cfg); err == nil {
		w.recovered(epoch, tr, start, cmp.Or(did, "nothing to fix"))
		return
	} else if w.current(epoch) {
		w.log.Warn("tunnel broken after "+tr.String(), "err", err)
	}
	w.ladder(ctx, tr, epoch, start, Ladder[1:])
}

// waitReady polls the direct network until it is online or ReadyTimeout.
func (w *Watchdog) waitReady(ctx context.Context, cfg Config, epoch int) Reach {
	deadline := w.clock.Now().Add(cfg.ReadyTimeout)
	for {
		r := w.t.Reach(ctx)
		if r == Online || !w.current(epoch) || !w.clock.Now().Before(deadline) {
			return r
		}
		if w.clock.Sleep(ctx, time.Second) != nil {
			return r
		}
	}
}

func (w *Watchdog) recover(ctx context.Context, tr Trigger, epoch int) {
	w.ladder(ctx, tr, epoch, w.clock.Now(), Ladder)
}

// ladder tries steps until a probe passes (ROADMAP 7.4).
func (w *Watchdog) ladder(ctx context.Context, tr Trigger, epoch int, start time.Time, steps []Step) {
	cfg := w.cfg().withDefaults()
	w.set(epoch, func(s *Status) { s.State, s.Problem, s.Detail = Recovering, ProblemNone, "" })
	var lastErr error
	for _, step := range steps {
		if !w.current(epoch) {
			return
		}
		if r := w.t.Reach(ctx); r != Online {
			w.offline(epoch, r)
			return
		}
		did, err := w.t.Recover(ctx, step)
		if errors.Is(err, ErrSkip) {
			continue
		}
		if !w.current(epoch) {
			return
		}
		if err != nil {
			w.log.Warn("recovery step failed", "step", step, "err", err)
			lastErr = err
			continue
		}
		if w.clock.Sleep(ctx, cfg.SettleTime) != nil {
			return
		}
		if err := w.probe(ctx, cfg); err != nil {
			w.log.Warn("recovery step didn't help", "step", step, "err", err)
			lastErr = err
			continue
		}
		w.recovered(epoch, tr, start, did)
		return
	}
	if !w.current(epoch) {
		return
	}
	detail := "recovery failed"
	if lastErr != nil {
		detail += ": " + lastErr.Error()
	}
	w.mu.Lock()
	w.backoff = min(max(2*w.backoff, cfg.MinBackoff), cfg.MaxBackoff)
	backoff := w.backoff
	w.mu.Unlock()
	w.log.Error("tunnel can't be recovered; will retry", "in", backoff, "err", lastErr)
	w.set(epoch, func(s *Status) {
		s.State, s.Problem, s.Detail = Failed, ProblemExhausted, detail
		s.Count++
		s.LastTrigger, s.LastAt, s.LastDuration, s.LastResult = tr, w.clock.Now(), w.clock.Now().Sub(start), detail
	})
}

func (w *Watchdog) probe(ctx context.Context, cfg Config) error {
	ctx, cancel := context.WithTimeout(ctx, cfg.ProbeTimeout)
	defer cancel()
	return w.t.Probe(ctx)
}

func (w *Watchdog) healthy(epoch int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.epoch != epoch {
		return
	}
	if w.st.State != Connected {
		w.log.Info("tunnel is healthy again")
	}
	w.failures, w.backoff = 0, 0
	w.st.State, w.st.Problem, w.st.Detail = Connected, ProblemNone, ""
}

func (w *Watchdog) recovered(epoch int, tr Trigger, start time.Time, did string) {
	now := w.clock.Now()
	w.log.Info("tunnel recovered", "trigger", tr, "by", did, "took", now.Sub(start).Round(time.Millisecond))
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.epoch != epoch {
		return
	}
	w.failures, w.backoff = 0, 0
	w.st.State, w.st.Problem, w.st.Detail = Connected, ProblemNone, ""
	w.st.Count++
	w.st.LastTrigger, w.st.LastAt, w.st.LastDuration, w.st.LastResult = tr, now, now.Sub(start), did
}

func (w *Watchdog) offline(epoch int, r Reach) {
	p, d := ProblemOffline, "waiting for the network"
	if r == Captive {
		p, d = ProblemCaptive, "the network needs a login (captive portal)"
	}
	w.set(epoch, func(s *Status) {
		if s.Problem != p {
			w.log.Info("not recovering: " + d)
		}
		s.State, s.Problem, s.Detail = Degraded, p, d
	})
	w.mu.Lock()
	w.failures = 0
	w.mu.Unlock()
}

func (w *Watchdog) set(epoch int, f func(*Status)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.epoch == epoch {
		f(&w.st)
	}
}

func (w *Watchdog) current(epoch int) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.epoch == epoch
}

// String formats a status for logs.
func (s Status) String() string {
	if s.Detail == "" {
		return s.State.String()
	}
	return fmt.Sprintf("%s (%s)", s.State, s.Detail)
}
