package daemon

import (
	"context"
	"errors"
	"time"

	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/core"
	"github.com/vvaeli/beryllium/internal/subscription"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type connectionService struct {
	berylliumv1.UnimplementedConnectionServiceServer
	c       *connector
	rt      *core.Runtime
	latency *latencyCache
}

var kindFromProto = map[berylliumv1.CoreKind]core.Kind{
	berylliumv1.CoreKind_CORE_KIND_SING_BOX: core.SingBox,
	berylliumv1.CoreKind_CORE_KIND_XRAY:     core.Xray,
	berylliumv1.CoreKind_CORE_KIND_MIHOMO:   core.Mihomo,
}

var kindToProto = map[core.Kind]berylliumv1.CoreKind{
	core.SingBox: berylliumv1.CoreKind_CORE_KIND_SING_BOX,
	core.Xray:    berylliumv1.CoreKind_CORE_KIND_XRAY,
	core.Mihomo:  berylliumv1.CoreKind_CORE_KIND_MIHOMO,
}

func (s *connectionService) Connect(ctx context.Context, req *berylliumv1.ConnectRequest) (*berylliumv1.ConnectResponse, error) {
	switch req.GetMode() {
	case berylliumv1.Mode_MODE_UNSPECIFIED, berylliumv1.Mode_MODE_LOCAL_PROXY, berylliumv1.Mode_MODE_SYSTEM_PROXY, berylliumv1.Mode_MODE_TUN:
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown mode %s", req.GetMode())
	}
	if err := s.c.connect(ctx, req); err != nil {
		return nil, err
	}
	return &berylliumv1.ConnectResponse{Status: s.status(ctx)}, nil
}

func (s *connectionService) Disconnect(ctx context.Context, _ *berylliumv1.DisconnectRequest) (*berylliumv1.DisconnectResponse, error) {
	s.c.disconnect(ctx)
	return &berylliumv1.DisconnectResponse{Status: s.status(ctx)}, nil
}

func (s *connectionService) GetStatus(ctx context.Context, _ *berylliumv1.GetStatusRequest) (*berylliumv1.GetStatusResponse, error) {
	return &berylliumv1.GetStatusResponse{Status: s.status(ctx)}, nil
}

// WatchStatus sends the status now, on every change and every second while
// connected (traffic).
func (s *connectionService) WatchStatus(_ *berylliumv1.WatchStatusRequest, stream berylliumv1.ConnectionService_WatchStatusServer) error {
	ctx := stream.Context()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var last *berylliumv1.ConnectionStatus
	for {
		cur := s.status(ctx)
		changed := last == nil || !proto.Equal(withoutTraffic(last), withoutTraffic(cur))
		if changed || cur.GetState() == berylliumv1.ConnectionState_CONNECTION_STATE_CONNECTED {
			if err := stream.Send(&berylliumv1.WatchStatusResponse{Status: cur}); err != nil {
				return err
			}
			last = cur
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func withoutTraffic(st *berylliumv1.ConnectionStatus) *berylliumv1.ConnectionStatus {
	c := proto.Clone(st).(*berylliumv1.ConnectionStatus)
	c.Traffic = nil
	return c
}

var stateToProto = map[core.State]berylliumv1.ConnectionState{
	core.StateDisconnected: berylliumv1.ConnectionState_CONNECTION_STATE_DISCONNECTED,
	core.StateConnecting:   berylliumv1.ConnectionState_CONNECTION_STATE_CONNECTING,
	core.StateConnected:    berylliumv1.ConnectionState_CONNECTION_STATE_CONNECTED,
	core.StateRecovering:   berylliumv1.ConnectionState_CONNECTION_STATE_RECOVERING,
	core.StateFailed:       berylliumv1.ConnectionState_CONNECTION_STATE_FAILED,
}

func (s *connectionService) status(ctx context.Context) *berylliumv1.ConnectionStatus {
	st := s.rt.Status()
	mode, subID := s.c.currentMode()
	p := &berylliumv1.ConnectionStatus{
		State:      stateToProto[st.State],
		Core:       kindToProto[st.Core],
		CoreReason: st.Reason,
		LocalProxy: st.LocalProxy,
		Recovery:   &berylliumv1.RecoveryStats{Count: uint32(st.Restarts)},
	}
	if st.State != core.StateDisconnected {
		p.Mode = mode
	}
	if st.Server != nil {
		p.Server = s.latency.annotate(serverToProto(*st.Server, subID))
	}
	if !st.Since.IsZero() {
		p.ConnectedSince = timestamppb.New(st.Since)
	}
	if st.Err != nil {
		reason := berylliumv1.ErrorReason_ERROR_REASON_CORE_START_FAILED
		if st.TUN {
			reason = berylliumv1.ErrorReason_ERROR_REASON_TUN_SETUP_FAILED
		}
		p.Error = &berylliumv1.ErrorDetail{Reason: reason, Message: st.Err.Error()}
	}
	applyWatchdog(p, s.c.wd.Status())
	if st.State == core.StateConnected {
		// Generous: right after a start the Clash API can be slow on a busy
		// machine, and missing counters look like a broken connection.
		tctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()
		if tr, err := s.rt.Traffic(tctx); err == nil {
			p.Traffic = &berylliumv1.TrafficStats{UploadBytesTotal: tr.Upload, DownloadBytesTotal: tr.Download,
				UploadBytesPerSec: tr.UploadRate, DownloadBytesPerSec: tr.DownloadRate}
		}
	}
	return p
}

// coreErr maps runtime errors. Like subErr it never uses Unavailable.
func coreErr(err error) error {
	if _, ok := status.FromError(err); ok && status.Code(err) != codes.Unknown {
		return err
	}
	switch {
	case errors.Is(err, core.ErrNoCore):
		return withReason(codes.FailedPrecondition, berylliumv1.ErrorReason_ERROR_REASON_NO_CORE_FOR_SERVER, err)
	case errors.Is(err, core.ErrNotInstalled):
		return withReason(codes.FailedPrecondition, berylliumv1.ErrorReason_ERROR_REASON_CORE_NOT_INSTALLED, err)
	case errors.Is(err, core.ErrTUNPrivileges):
		return withReason(codes.FailedPrecondition, berylliumv1.ErrorReason_ERROR_REASON_TUN_SETUP_FAILED, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	default:
		return withReason(codes.FailedPrecondition, berylliumv1.ErrorReason_ERROR_REASON_CORE_START_FAILED, err)
	}
}

type testService struct {
	berylliumv1.UnimplementedTestServiceServer
	rt      *core.Runtime
	subs    *subscription.Manager
	pinger  *core.Pinger
	latency *latencyCache
}

//nolint:revive // name is fixed by the generated gRPC interface
func (s *testService) UrlTest(ctx context.Context, req *berylliumv1.UrlTestRequest) (*berylliumv1.UrlTestResponse, error) {
	if s.rt.Status().State != core.StateConnected {
		return nil, status.Error(codes.FailedPrecondition, "not connected")
	}
	// A failed test is a result for the caller, not an RPC error.
	lat, testErr := s.rt.URLTest(ctx, req.GetUrl())
	resp := &berylliumv1.UrlTestResponse{Ok: testErr == nil}
	if testErr != nil {
		resp.Error = &berylliumv1.ErrorDetail{Reason: berylliumv1.ErrorReason_ERROR_REASON_NETWORK_UNAVAILABLE, Message: testErr.Error()}
	} else {
		resp.Latency = durationpb.New(lat)
	}
	return resp, nil
}
