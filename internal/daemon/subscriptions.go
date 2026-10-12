package daemon

import (
	"context"
	"errors"
	"strings"
	"time"

	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/link"
	"github.com/vvaeli/beryllium/internal/model"
	"github.com/vvaeli/beryllium/internal/redact"
	"github.com/vvaeli/beryllium/internal/routing"
	"github.com/vvaeli/beryllium/internal/subscription"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type subscriptionService struct {
	berylliumv1.UnimplementedSubscriptionServiceServer
	subs    *subscription.Manager
	latency *latencyCache
	routes  *routing.Manager
}

func (s *subscriptionService) AddSubscription(ctx context.Context, req *berylliumv1.AddSubscriptionRequest) (*berylliumv1.AddSubscriptionResponse, error) {
	rec, err := s.subs.Add(ctx, req.GetUrl(), strings.TrimSpace(req.GetName()))
	if err != nil {
		return nil, subErr(err)
	}
	return &berylliumv1.AddSubscriptionResponse{Subscription: subToProto(rec)}, nil
}

func (s *subscriptionService) ListSubscriptions(context.Context, *berylliumv1.ListSubscriptionsRequest) (*berylliumv1.ListSubscriptionsResponse, error) {
	resp := &berylliumv1.ListSubscriptionsResponse{}
	for _, r := range s.subs.List() {
		resp.Subscriptions = append(resp.Subscriptions, subToProto(r))
	}
	return resp, nil
}

func (s *subscriptionService) RemoveSubscription(_ context.Context, req *berylliumv1.RemoveSubscriptionRequest) (*berylliumv1.RemoveSubscriptionResponse, error) {
	if err := s.subs.Remove(req.GetId()); err != nil {
		return nil, subErr(err)
	}
	return &berylliumv1.RemoveSubscriptionResponse{}, nil
}

func (s *subscriptionService) UpdateSubscription(_ context.Context, req *berylliumv1.UpdateSubscriptionRequest) (*berylliumv1.UpdateSubscriptionResponse, error) {
	var interval *time.Duration
	if req.AutoUpdateInterval != nil {
		d := req.GetAutoUpdateInterval().AsDuration()
		if d < 0 {
			return nil, status.Error(codes.InvalidArgument, "interval must not be negative")
		}
		interval = &d
	}
	rec, err := s.subs.Update(req.GetId(), req.Name, interval)
	if err != nil {
		return nil, subErr(err)
	}
	return &berylliumv1.UpdateSubscriptionResponse{Subscription: subToProto(rec)}, nil
}

func (s *subscriptionService) RefreshSubscription(ctx context.Context, req *berylliumv1.RefreshSubscriptionRequest) (*berylliumv1.RefreshSubscriptionResponse, error) {
	rec, err := s.subs.Refresh(ctx, req.GetId())
	if err != nil {
		return nil, subErr(err)
	}
	return &berylliumv1.RefreshSubscriptionResponse{Subscription: subToProto(rec)}, nil
}

// RefreshAllSubscriptions reports per-subscription failures via last_error.
func (s *subscriptionService) RefreshAllSubscriptions(ctx context.Context, _ *berylliumv1.RefreshAllSubscriptionsRequest) (*berylliumv1.RefreshAllSubscriptionsResponse, error) {
	recs, _ := s.subs.RefreshAll(ctx)
	resp := &berylliumv1.RefreshAllSubscriptionsResponse{}
	for _, r := range recs {
		resp.Subscriptions = append(resp.Subscriptions, subToProto(r))
	}
	return resp, nil
}

func (s *subscriptionService) ListServers(_ context.Context, req *berylliumv1.ListServersRequest) (*berylliumv1.ListServersResponse, error) {
	resp := &berylliumv1.ListServersResponse{}
	if req.GetSubscriptionId() == "" {
		for _, r := range s.subs.List() {
			for _, srv := range r.Servers {
				resp.Servers = append(resp.Servers, s.latency.annotate(serverToProto(*srv, r.ID)))
			}
		}
		return resp, nil
	}
	servers, err := s.subs.Servers(req.GetSubscriptionId())
	if err != nil {
		return nil, subErr(err)
	}
	for _, srv := range servers {
		resp.Servers = append(resp.Servers, s.latency.annotate(serverToProto(srv, req.GetSubscriptionId())))
	}
	return resp, nil
}

func (s *subscriptionService) ImportConfig(_ context.Context, req *berylliumv1.ImportConfigRequest) (*berylliumv1.ImportConfigResponse, error) {
	content := req.GetFileContent()
	if req.GetUri() != "" {
		content = []byte(req.GetUri())
	}
	if len(content) == 0 {
		return nil, status.Error(codes.InvalidArgument, "nothing to import")
	}
	rec, err := s.subs.Import(content, req.GetFileName(), strings.TrimSpace(req.GetName()))
	if err != nil {
		return nil, subErr(err)
	}
	return &berylliumv1.ImportConfigResponse{Subscription: subToProto(rec)}, nil
}

func (s *subscriptionService) GetShareLink(_ context.Context, req *berylliumv1.GetShareLinkRequest) (*berylliumv1.GetShareLinkResponse, error) {
	switch t := req.GetTarget().(type) {
	case *berylliumv1.GetShareLinkRequest_SubscriptionId:
		rec, err := s.subs.Get(t.SubscriptionId)
		if err != nil {
			return nil, subErr(err)
		}
		if rec.Kind != subscription.KindRemote {
			return nil, status.Error(codes.FailedPrecondition, "imported configs have no subscription URL; share individual servers instead")
		}
		return &berylliumv1.GetShareLinkResponse{Uri: rec.URL}, nil
	case *berylliumv1.GetShareLinkRequest_ServerId:
		srv, _, err := s.subs.Server(t.ServerId)
		if err != nil {
			return nil, subErr(err)
		}
		uri, err := link.Encode(&srv)
		if err != nil {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return &berylliumv1.GetShareLinkResponse{Uri: uri}, nil
	case *berylliumv1.GetShareLinkRequest_RoutingProfileId:
		r, _, err := s.routes.Get(t.RoutingProfileId)
		if err != nil {
			return nil, routingErr(err)
		}
		uri, err := r.Profile.Link()
		if err != nil {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return &berylliumv1.GetShareLinkResponse{Uri: uri}, nil
	default:
		return nil, status.Error(codes.InvalidArgument, "target is required")
	}
}

// subErr maps manager errors to gRPC statuses. Download failures must not
// use Unavailable: clients read that as "daemon unreachable".
func subErr(err error) error {
	switch {
	case errors.Is(err, subscription.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, subscription.ErrFetch):
		return withReason(codes.FailedPrecondition, berylliumv1.ErrorReason_ERROR_REASON_SUBSCRIPTION_FETCH_FAILED, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	default:
		return withReason(codes.InvalidArgument, berylliumv1.ErrorReason_ERROR_REASON_SUBSCRIPTION_PARSE_FAILED, err)
	}
}

func withReason(code codes.Code, reason berylliumv1.ErrorReason, err error) error {
	msg := redact.String(err.Error())
	st, derr := status.New(code, msg).WithDetails(&berylliumv1.ErrorDetail{Reason: reason, Message: msg})
	if derr != nil {
		return status.Error(code, msg)
	}
	return st.Err()
}

func subToProto(r subscription.Record) *berylliumv1.Subscription {
	p := &berylliumv1.Subscription{
		Id:                 r.ID,
		Name:               r.Name,
		UrlMasked:          redact.String(r.URL),
		ProviderTitle:      r.ProviderTitle,
		SupportUrl:         r.SupportURL,
		AutoUpdateInterval: durationpb.New(r.Interval()),
		LastError:          r.LastError,
		ServerCount:        uint32(len(r.Servers)),
	}
	if !r.UpdatedAt.IsZero() {
		p.UpdatedAt = timestamppb.New(r.UpdatedAt)
	}
	switch r.Kind {
	case subscription.KindRemote:
		p.Kind = berylliumv1.SubscriptionKind_SUBSCRIPTION_KIND_REMOTE
	case subscription.KindLocal:
		p.Kind = berylliumv1.SubscriptionKind_SUBSCRIPTION_KIND_LOCAL
	}
	if q := r.Quota; q != nil {
		p.Quota = &berylliumv1.Quota{UploadBytes: q.Upload, DownloadBytes: q.Download, TotalBytes: q.Total}
		if !q.Expire.IsZero() {
			p.Quota.ExpiresAt = timestamppb.New(q.Expire)
		}
	}
	return p
}

var protocolToProto = map[model.Protocol]berylliumv1.Protocol{
	model.VLESS:       berylliumv1.Protocol_PROTOCOL_VLESS,
	model.VMess:       berylliumv1.Protocol_PROTOCOL_VMESS,
	model.Trojan:      berylliumv1.Protocol_PROTOCOL_TROJAN,
	model.Shadowsocks: berylliumv1.Protocol_PROTOCOL_SHADOWSOCKS,
	model.Hysteria2:   berylliumv1.Protocol_PROTOCOL_HYSTERIA2,
	model.TUIC:        berylliumv1.Protocol_PROTOCOL_TUIC,
	model.WireGuard:   berylliumv1.Protocol_PROTOCOL_WIREGUARD,
	model.AmneziaWG:   berylliumv1.Protocol_PROTOCOL_AMNEZIAWG,
}

var transportToProto = map[string]berylliumv1.Transport{
	"tcp":         berylliumv1.Transport_TRANSPORT_TCP,
	"ws":          berylliumv1.Transport_TRANSPORT_WS,
	"grpc":        berylliumv1.Transport_TRANSPORT_GRPC,
	"http":        berylliumv1.Transport_TRANSPORT_HTTP2,
	"httpupgrade": berylliumv1.Transport_TRANSPORT_HTTPUPGRADE,
	"xhttp":       berylliumv1.Transport_TRANSPORT_XHTTP,
	"quic":        berylliumv1.Transport_TRANSPORT_QUIC,
}

func serverToProto(s model.Server, subID string) *berylliumv1.Server {
	p := &berylliumv1.Server{
		Id:             s.ID,
		SubscriptionId: subID,
		Name:           s.Name,
		Protocol:       protocolToProto[s.Protocol],
		Address:        s.Address,
		Port:           uint32(s.Port),
		CountryCode:    s.Country,
		Security:       berylliumv1.Security_SECURITY_NONE,
	}
	switch {
	case s.Transport != nil:
		p.Transport = transportToProto[s.Transport.Type]
	case s.Protocol == model.Hysteria2 || s.Protocol == model.TUIC:
		p.Transport = berylliumv1.Transport_TRANSPORT_QUIC
	case s.Protocol == model.WireGuard || s.Protocol == model.AmneziaWG:
		p.Transport = berylliumv1.Transport_TRANSPORT_UDP
	default:
		p.Transport = berylliumv1.Transport_TRANSPORT_TCP
	}
	if s.TLS != nil {
		p.Security = berylliumv1.Security_SECURITY_TLS
		if s.TLS.Security == "reality" {
			p.Security = berylliumv1.Security_SECURITY_REALITY
		}
	}
	return p
}
