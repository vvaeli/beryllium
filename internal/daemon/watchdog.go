package daemon

import (
	"context"
	"errors"
	"time"

	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/core"
	"github.com/vvaeli/beryllium/internal/model"
	"github.com/vvaeli/beryllium/internal/netwatch"
	"github.com/vvaeli/beryllium/internal/watchdog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// recoveryTarget lets the watchdog check and repair the connector's
// connection.
type recoveryTarget struct{ c *connector }

func (t recoveryTarget) Active() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	return t.c.up
}

func (t recoveryTarget) Probe(ctx context.Context) error {
	_, err := t.c.rt.Probe(ctx, t.c.probeURLs)
	return err
}

func (t recoveryTarget) Reach(ctx context.Context) watchdog.Reach {
	if t.c.reach != nil {
		return t.c.reach(ctx)
	}
	n, err := netwatch.Current(core.TUNPrefixes())
	if err != nil {
		return watchdog.Offline
	}
	switch netwatch.Check(ctx, n) {
	case netwatch.Online:
		return watchdog.Online
	case netwatch.Captive:
		return watchdog.Captive
	}
	return watchdog.Offline
}

// AfterWake flushes the OS DNS cache in the background: it only matters to
// apps (sing-box resolves on its own), and dscacheutil can take seconds,
// which would delay the tunnel check.
func (t recoveryTarget) AfterWake(ctx context.Context) {
	go netwatch.FlushDNS(context.WithoutCancel(ctx))
}

func (t recoveryTarget) Recover(ctx context.Context, s watchdog.Step) (string, error) {
	c := t.c
	switch s {
	case watchdog.StepResetConnections:
		if err := c.rt.ResetConnections(ctx); err != nil {
			return "", err
		}
		return "closed stale connections", nil
	case watchdog.StepRestartCore:
		return c.restartWith(ctx, func(srv model.Server, cur core.Kind, reason string) (model.Server, core.Kind, string, string, error) {
			return srv, cur, reason, "restarted " + string(cur), nil
		})
	case watchdog.StepSwitchServer:
		return c.switchServer(ctx)
	case watchdog.StepSwitchCore:
		return c.restartWith(ctx, func(srv model.Server, cur core.Kind, _ string) (model.Server, core.Kind, string, string, error) {
			if c.opts.Core != "" {
				return srv, "", "", "", watchdog.ErrSkip // the user picked the core
			}
			for _, k := range core.Kinds {
				if k == cur {
					continue
				}
				if _, err := core.Choose(&srv, k, c.bins.Installed); err == nil {
					return srv, k, "recovery: the tunnel didn't work on " + string(cur), "switched to " + string(k), nil
				}
			}
			return srv, "", "", "", watchdog.ErrSkip
		})
	}
	return "", watchdog.ErrSkip
}

// corePick chooses what to reconnect with from the current server, core
// and core reason: a server, a core ("" to choose again), the core reason
// and a description of the step.
type corePick func(srv model.Server, cur core.Kind, reason string) (model.Server, core.Kind, string, string, error)

// restartWith reconnects as pick says, keeping the mode and routing. It
// uses the remembered server and options, so it works even after the
// runtime gave up on a crashing core.
func (c *connector) restartWith(ctx context.Context, pick corePick) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.up {
		return "", watchdog.ErrSkip
	}
	srv, k, reason, did, err := pick(c.srv, c.core, c.coreReason)
	if err != nil {
		return "", err
	}
	opts := c.opts
	opts.Core, opts.CoreReason = k, reason
	st, err := c.rt.Connect(ctx, srv, opts)
	if err != nil {
		return "", err
	}
	c.srv, c.core, c.coreReason = srv, st.Core, st.Reason
	o := ownerOf(c.proxy)
	if err := c.syncProxy(ctx, o); err != nil {
		c.log.Warn("system proxy failed after recovery", "err", err)
	}
	return did, nil
}

// switchServer moves an auto-selected connection to the fastest other
// server; a server the user picked is never switched.
func (c *connector) switchServer(ctx context.Context) (string, error) {
	c.mu.Lock()
	auto, subFilter, curID := c.auto, c.subFilter, c.srv.ID
	c.mu.Unlock()
	if !auto {
		return "", watchdog.ErrSkip
	}
	servers, err := c.subs.Servers(subFilter)
	if err != nil {
		return "", err
	}
	var others []model.Server
	for _, s := range servers {
		if s.ID != curID {
			others = append(others, s)
		}
	}
	if len(others) == 0 {
		return "", watchdog.ErrSkip
	}
	// Measure now: cached latencies are from before the network changed.
	results := make(chan core.PingResult)
	go func() {
		c.pinger.Ping(ctx, others, core.PingOptions{Method: core.PingHTTP, Timeout: defaultPingTimeout}, results)
		close(results)
	}()
	for r := range results {
		c.latency.put(r.ServerID, r.Latency)
	}
	best, ok := c.latency.fastest(others)
	if !ok {
		return "", errors.New("no other server responded")
	}
	return c.restartWith(ctx, func(model.Server, core.Kind, string) (model.Server, core.Kind, string, string, error) {
		return best, "", "", "switched to " + best.Name, nil
	})
}

// watchdogConfig reads the watchdog settings.
func (c *connector) watchdogConfig() watchdog.Config {
	w := c.settings.get().GetWatchdog()
	return watchdog.Config{Interval: w.GetInterval().AsDuration(), Threshold: int(w.GetFailureThreshold())}
}

var triggerToProto = map[watchdog.Trigger]berylliumv1.RecoveryTrigger{
	watchdog.TriggerWatchdog:  berylliumv1.RecoveryTrigger_RECOVERY_TRIGGER_WATCHDOG,
	watchdog.TriggerWake:      berylliumv1.RecoveryTrigger_RECOVERY_TRIGGER_WAKE,
	watchdog.TriggerNetChange: berylliumv1.RecoveryTrigger_RECOVERY_TRIGGER_NETWORK_CHANGE,
}

var watchdogStateToProto = map[watchdog.State]berylliumv1.ConnectionState{
	watchdog.Degraded:   berylliumv1.ConnectionState_CONNECTION_STATE_DEGRADED,
	watchdog.Recovering: berylliumv1.ConnectionState_CONNECTION_STATE_RECOVERING,
	watchdog.Failed:     berylliumv1.ConnectionState_CONNECTION_STATE_FAILED,
}

// applyWatchdog overlays the watchdog's view on a status built from the
// runtime: the runtime only knows whether the cores run, the watchdog
// whether traffic flows.
func applyWatchdog(p *berylliumv1.ConnectionStatus, w watchdog.Status) {
	if w.State == watchdog.Idle || p.GetState() == berylliumv1.ConnectionState_CONNECTION_STATE_DISCONNECTED {
		return
	}
	if s, ok := watchdogStateToProto[w.State]; ok && p.GetState() != berylliumv1.ConnectionState_CONNECTION_STATE_FAILED {
		p.State = s
		reason := berylliumv1.ErrorReason_ERROR_REASON_NETWORK_UNAVAILABLE
		if w.Problem == watchdog.ProblemCaptive {
			reason = berylliumv1.ErrorReason_ERROR_REASON_CAPTIVE_PORTAL
		}
		if w.Detail != "" {
			p.Error = &berylliumv1.ErrorDetail{Reason: reason, Message: w.Detail}
		}
	}
	r := p.GetRecovery()
	if r == nil {
		r = &berylliumv1.RecoveryStats{}
		p.Recovery = r
	}
	r.Count += uint32(w.Count)
	if w.Count > 0 {
		r.LastTrigger = triggerToProto[w.LastTrigger]
		r.LastAt = timestamppb.New(w.LastAt)
		r.LastDuration = durationpb.New(w.LastDuration)
		r.LastResult = w.LastResult
	}
}

var simulated = map[berylliumv1.SimulatedEvent]watchdog.Trigger{
	berylliumv1.SimulatedEvent_SIMULATED_EVENT_WAKE:           watchdog.TriggerWake,
	berylliumv1.SimulatedEvent_SIMULATED_EVENT_NETWORK_CHANGE: watchdog.TriggerNetChange,
	berylliumv1.SimulatedEvent_SIMULATED_EVENT_HEALTH_CHECK:   watchdog.TriggerWatchdog,
}

func (s *daemonService) SimulateEvent(ctx context.Context, req *berylliumv1.SimulateEventRequest) (*berylliumv1.SimulateEventResponse, error) {
	if !(recoveryTarget{s.d.conn}).Active() {
		return nil, status.Error(codes.FailedPrecondition, "not connected")
	}
	ev := req.GetEvent()
	s.d.log.Info("simulating event", "event", ev.String())
	if ev == berylliumv1.SimulatedEvent_SIMULATED_EVENT_SLEEP {
		s.d.wd.Sleep(ctx)
		return &berylliumv1.SimulateEventResponse{}, nil
	}
	tr, ok := simulated[ev]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unknown event %s", ev)
	}
	// Recovery can take a while (network wait, server switch).
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	s.d.wd.Trigger(ctx, tr, true)
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	return &berylliumv1.SimulateEventResponse{}, nil
}
