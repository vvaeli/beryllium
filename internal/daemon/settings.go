package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/routing"
	"github.com/vvaeli/beryllium/internal/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
)

// settingsStore keeps Settings as protojson inside the versioned store, so
// the proto stays the single schema.
type settingsStore struct {
	st *store.Store[json.RawMessage]

	mu  sync.Mutex
	cur *berylliumv1.Settings
	// onChange runs after a successful update with the previous settings
	// and the updated paths (empty: everything).
	onChange func(old, cur *berylliumv1.Settings, paths []string)
}

func defaultSettings() *berylliumv1.Settings {
	return &berylliumv1.Settings{
		Mode: berylliumv1.Mode_MODE_LOCAL_PROXY,
		Routing: &berylliumv1.RoutingSettings{
			ApplyProviderRouting: true,
		},
		Dns: &berylliumv1.DnsSettings{Ipv6: berylliumv1.Ipv6Mode_IPV6_MODE_BLOCK},
		Watchdog: &berylliumv1.WatchdogSettings{
			Interval:         durationpb.New(30 * time.Second),
			FailureThreshold: 3,
		},
		LogLevel: berylliumv1.LogLevel_LOG_LEVEL_INFO,
	}
}

func openSettings(st *store.Store[json.RawMessage]) (*settingsStore, error) {
	raw, err := st.Load()
	if err != nil {
		return nil, err
	}
	cur := defaultSettings()
	if len(raw) > 0 && string(raw) != "null" {
		loaded := &berylliumv1.Settings{}
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, loaded); err != nil {
			return nil, fmt.Errorf("settings: %w", err)
		}
		// Fields absent from the file keep their defaults.
		proto.Merge(cur, loaded)
		if loaded.GetRouting() != nil && !loaded.GetRouting().GetApplyProviderRouting() {
			cur.Routing.ApplyProviderRouting = false
		}
	}
	return &settingsStore{st: st, cur: cur}, nil
}

func (s *settingsStore) get() *berylliumv1.Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return proto.Clone(s.cur).(*berylliumv1.Settings)
}

// update applies the fields named in mask (all fields when empty).
func (s *settingsStore) update(in *berylliumv1.Settings, mask []string) (*berylliumv1.Settings, error) {
	s.mu.Lock()
	old := proto.Clone(s.cur).(*berylliumv1.Settings)
	next := proto.Clone(s.cur).(*berylliumv1.Settings)
	if len(mask) == 0 {
		next = proto.Clone(in).(*berylliumv1.Settings)
	} else {
		for _, path := range mask {
			if err := copyPath(next.ProtoReflect(), in.ProtoReflect(), strings.Split(path, ".")); err != nil {
				s.mu.Unlock()
				return nil, status.Error(codes.InvalidArgument, err.Error())
			}
		}
	}
	if err := validateSettings(next); err != nil {
		s.mu.Unlock()
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	raw, err := protojson.Marshal(next)
	if err == nil {
		err = s.st.Save(raw)
	}
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	s.cur = next
	cb := s.onChange
	s.mu.Unlock()
	if cb != nil {
		cb(old, proto.Clone(next).(*berylliumv1.Settings), mask)
	}
	return proto.Clone(next).(*berylliumv1.Settings), nil
}

// copyPath copies the field at path from src into dst, creating parent
// messages as needed.
func copyPath(dst, src protoreflect.Message, path []string) error {
	fd := dst.Descriptor().Fields().ByName(protoreflect.Name(path[0]))
	if fd == nil {
		return fmt.Errorf("unknown settings field %q", path[0])
	}
	if len(path) == 1 {
		if src.Has(fd) {
			dst.Set(fd, src.Get(fd))
		} else {
			dst.Clear(fd)
		}
		return nil
	}
	if fd.Message() == nil || fd.IsList() || fd.IsMap() {
		return fmt.Errorf("settings field %q has no subfields", path[0])
	}
	return copyPath(dst.Mutable(fd).Message(), src.Get(fd).Message(), path[1:])
}

func validateSettings(s *berylliumv1.Settings) error {
	switch s.GetMode() {
	case berylliumv1.Mode_MODE_TUN, berylliumv1.Mode_MODE_SYSTEM_PROXY, berylliumv1.Mode_MODE_LOCAL_PROXY:
	default:
		return fmt.Errorf("mode %s is not valid", s.GetMode())
	}
	for i, r := range s.GetRouting().GetRules() {
		if err := ruleFromProto(r).Validate(); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	if d := s.GetDns(); d != nil {
		if err := routing.ValidateResolver(d.GetRemoteDns()); d.GetRemoteDns() != "" && err != nil {
			return fmt.Errorf("remote DNS: %w", err)
		}
		if err := routing.ValidateResolver(d.GetDirectDns()); d.GetDirectDns() != "" && err != nil {
			return fmt.Errorf("direct DNS: %w", err)
		}
	}
	if iv := s.GetSubscriptionUpdateInterval(); iv != nil && iv.AsDuration() < 0 {
		return fmt.Errorf("subscription update interval can't be negative")
	}
	return nil
}

var matchFromProto = map[berylliumv1.RuleMatch]routing.Match{
	berylliumv1.RuleMatch_RULE_MATCH_DOMAIN:         routing.MatchDomain,
	berylliumv1.RuleMatch_RULE_MATCH_DOMAIN_SUFFIX:  routing.MatchDomainSuffix,
	berylliumv1.RuleMatch_RULE_MATCH_DOMAIN_KEYWORD: routing.MatchDomainKeyword,
	berylliumv1.RuleMatch_RULE_MATCH_IP_CIDR:        routing.MatchIPCIDR,
	berylliumv1.RuleMatch_RULE_MATCH_PROCESS_NAME:   routing.MatchProcessName,
	berylliumv1.RuleMatch_RULE_MATCH_PROCESS_PATH:   routing.MatchProcessPath,
}

var actionFromProto = map[berylliumv1.RuleAction]routing.Action{
	berylliumv1.RuleAction_RULE_ACTION_PROXY:  routing.ActionProxy,
	berylliumv1.RuleAction_RULE_ACTION_DIRECT: routing.ActionDirect,
	berylliumv1.RuleAction_RULE_ACTION_BLOCK:  routing.ActionBlock,
}

func ruleFromProto(r *berylliumv1.RoutingRule) routing.UserRule {
	return routing.UserRule{Match: matchFromProto[r.GetMatch()], Value: r.GetValue(), Action: actionFromProto[r.GetAction()]}
}

type settingsService struct {
	berylliumv1.UnimplementedSettingsServiceServer
	s *settingsStore
}

func (s *settingsService) GetSettings(context.Context, *berylliumv1.GetSettingsRequest) (*berylliumv1.GetSettingsResponse, error) {
	return &berylliumv1.GetSettingsResponse{Settings: s.s.get()}, nil
}

func (s *settingsService) UpdateSettings(_ context.Context, req *berylliumv1.UpdateSettingsRequest) (*berylliumv1.UpdateSettingsResponse, error) {
	if req.GetSettings() == nil {
		return nil, status.Error(codes.InvalidArgument, "settings are required")
	}
	cur, err := s.s.update(req.GetSettings(), req.GetUpdateMask().GetPaths())
	if err != nil {
		return nil, err
	}
	return &berylliumv1.UpdateSettingsResponse{Settings: cur}, nil
}
