package daemon

import (
	"context"
	"errors"
	"sync"
	"time"

	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/core"
	"github.com/vvaeli/beryllium/internal/subscription"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type connectionService struct {
	berylliumv1.UnimplementedConnectionServiceServer
	rt   *core.Runtime
	subs *subscription.Manager

	mu    sync.Mutex
	subID string // subscription of the connected server
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
	case berylliumv1.Mode_MODE_UNSPECIFIED, berylliumv1.Mode_MODE_LOCAL_PROXY:
	default:
		return nil, status.Errorf(codes.Unimplemented, "%s is not implemented yet; use the local proxy mode", req.GetMode())
	}
	if req.GetServerId() == "" {
		return nil, status.Error(codes.InvalidArgument, "choose a server; automatic selection is not implemented yet")
	}
	srv, subID, err := s.subs.Server(req.GetServerId())
	if err != nil {
		return nil, subErr(err)
	}
	if _, err := s.rt.Connect(ctx, srv, kindFromProto[req.GetCore()]); err != nil {
		return nil, coreErr(err)
	}
	s.mu.Lock()
	s.subID = subID
	s.mu.Unlock()
	return &berylliumv1.ConnectResponse{Status: s.status(ctx)}, nil
}

func (s *connectionService) Disconnect(ctx context.Context, _ *berylliumv1.DisconnectRequest) (*berylliumv1.DisconnectResponse, error) {
	s.rt.Disconnect()
	return &berylliumv1.DisconnectResponse{Status: s.status(ctx)}, nil
}

func (s *connectionService) GetStatus(ctx context.Context, _ *berylliumv1.GetStatusRequest) (*berylliumv1.GetStatusResponse, error) {
	return &berylliumv1.GetStatusResponse{Status: s.status(ctx)}, nil
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
	p := &berylliumv1.ConnectionStatus{
		State:      stateToProto[st.State],
		Core:       kindToProto[st.Core],
		CoreReason: st.Reason,
		LocalProxy: st.LocalProxy,
		Recovery:   &berylliumv1.RecoveryStats{Count: uint32(st.Restarts)},
	}
	if st.State != core.StateDisconnected {
		p.Mode = berylliumv1.Mode_MODE_LOCAL_PROXY
	}
	if st.Server != nil {
		s.mu.Lock()
		p.Server = serverToProto(*st.Server, s.subID)
		s.mu.Unlock()
	}
	if !st.Since.IsZero() {
		p.ConnectedSince = timestamppb.New(st.Since)
	}
	if st.Err != nil {
		p.Error = &berylliumv1.ErrorDetail{Reason: berylliumv1.ErrorReason_ERROR_REASON_CORE_START_FAILED, Message: st.Err.Error()}
	}
	if st.State == core.StateConnected {
		tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
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
	switch {
	case errors.Is(err, core.ErrNoCore):
		return withReason(codes.FailedPrecondition, berylliumv1.ErrorReason_ERROR_REASON_NO_CORE_FOR_SERVER, err)
	case errors.Is(err, core.ErrNotInstalled):
		return withReason(codes.FailedPrecondition, berylliumv1.ErrorReason_ERROR_REASON_CORE_NOT_INSTALLED, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	default:
		return withReason(codes.FailedPrecondition, berylliumv1.ErrorReason_ERROR_REASON_CORE_START_FAILED, err)
	}
}

type testService struct {
	berylliumv1.UnimplementedTestServiceServer
	rt *core.Runtime
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
