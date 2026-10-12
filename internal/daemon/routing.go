package daemon

import (
	"context"
	"errors"

	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/routing"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type routingService struct {
	berylliumv1.UnimplementedRoutingServiceServer
	routes *routing.Manager
}

func (s *routingService) ListRoutingProfiles(context.Context, *berylliumv1.ListRoutingProfilesRequest) (*berylliumv1.ListRoutingProfilesResponse, error) {
	list, active := s.routes.List()
	resp := &berylliumv1.ListRoutingProfilesResponse{}
	for _, r := range list {
		resp.Profiles = append(resp.Profiles, profileToProto(r, r.ID == active))
	}
	return resp, nil
}

func (s *routingService) ImportRoutingProfile(ctx context.Context, req *berylliumv1.ImportRoutingProfileRequest) (*berylliumv1.ImportRoutingProfileResponse, error) {
	src := req.GetUri()
	if src == "" {
		src = req.GetJson()
	}
	if src == "" {
		return nil, status.Error(codes.InvalidArgument, "uri or json is required")
	}
	var activate *bool
	if req.Activate != nil {
		activate = req.Activate
	}
	r, err := s.routes.Import(ctx, src, activate, routing.SourceImported, "")
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &berylliumv1.ImportRoutingProfileResponse{Profile: s.toProto(r)}, nil
}

func (s *routingService) ActivateRoutingProfile(_ context.Context, req *berylliumv1.ActivateRoutingProfileRequest) (*berylliumv1.ActivateRoutingProfileResponse, error) {
	r, err := s.routes.Activate(req.GetId())
	if err != nil {
		return nil, routingErr(err)
	}
	return &berylliumv1.ActivateRoutingProfileResponse{Profile: s.toProto(r)}, nil
}

func (s *routingService) RemoveRoutingProfile(_ context.Context, req *berylliumv1.RemoveRoutingProfileRequest) (*berylliumv1.RemoveRoutingProfileResponse, error) {
	if err := s.routes.Remove(req.GetId()); err != nil {
		return nil, routingErr(err)
	}
	return &berylliumv1.RemoveRoutingProfileResponse{}, nil
}

func (s *routingService) RefreshGeoData(ctx context.Context, req *berylliumv1.RefreshGeoDataRequest) (*berylliumv1.RefreshGeoDataResponse, error) {
	r, err := s.routes.RefreshGeo(ctx, req.GetId())
	if errors.Is(err, routing.ErrNotFound) {
		return nil, routingErr(err)
	}
	// A failed download is reported in the profile (last_error).
	return &berylliumv1.RefreshGeoDataResponse{Profile: s.toProto(r)}, nil
}

func (s *routingService) toProto(r routing.Record) *berylliumv1.RoutingProfile {
	_, active := s.routes.List()
	return profileToProto(r, r.ID == active)
}

func routingErr(err error) error {
	if errors.Is(err, routing.ErrNotFound) {
		return status.Error(codes.NotFound, err.Error())
	}
	return status.Error(codes.FailedPrecondition, err.Error())
}

var sourceToProto = map[routing.Source]berylliumv1.RoutingProfileSource{
	routing.SourceBuiltin:      berylliumv1.RoutingProfileSource_ROUTING_PROFILE_SOURCE_BUILTIN,
	routing.SourceSubscription: berylliumv1.RoutingProfileSource_ROUTING_PROFILE_SOURCE_SUBSCRIPTION,
	routing.SourceImported:     berylliumv1.RoutingProfileSource_ROUTING_PROFILE_SOURCE_IMPORTED,
}

var geoToProto = map[routing.GeoState]berylliumv1.GeoDataState{
	routing.GeoNotNeeded:   berylliumv1.GeoDataState_GEO_DATA_STATE_NOT_NEEDED,
	routing.GeoDownloading: berylliumv1.GeoDataState_GEO_DATA_STATE_DOWNLOADING,
	routing.GeoReady:       berylliumv1.GeoDataState_GEO_DATA_STATE_READY,
	routing.GeoFailed:      berylliumv1.GeoDataState_GEO_DATA_STATE_FAILED,
}

func profileToProto(r routing.Record, active bool) *berylliumv1.RoutingProfile {
	p := r.Profile
	out := &berylliumv1.RoutingProfile{
		Id:              r.ID,
		Name:            p.Name,
		Source:          sourceToProto[r.Source],
		SubscriptionId:  r.SubscriptionID,
		Active:          active,
		GlobalProxy:     p.GlobalProxy,
		DirectRuleCount: uint32(len(p.DirectSites) + len(p.DirectIP)),
		ProxyRuleCount:  uint32(len(p.ProxySites) + len(p.ProxyIP)),
		BlockRuleCount:  uint32(len(p.BlockSites) + len(p.BlockIP)),
		GeoDataState:    geoToProto[r.GeoState],
		LastError:       r.LastError,
	}
	if !p.LastUpdated.IsZero() {
		out.LastUpdated = timestamppb.New(p.LastUpdated)
	}
	return out
}
