package daemon

import (
	"sync"
	"time"

	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/core"
	"github.com/vvaeli/beryllium/internal/model"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// latencyCache keeps the last HTTP measurement per server for ListServers.
// TCP/ICMP results are not cached: a reachable host says nothing about
// whether the proxy works, and they would mislead sorting and auto-select.
type latencyCache struct {
	mu sync.Mutex
	m  map[string]latencyEntry
}

type latencyEntry struct {
	latency time.Duration // 0 when the last test failed
	at      time.Time
}

func newLatencyCache() *latencyCache { return &latencyCache{m: map[string]latencyEntry{}} }

func (c *latencyCache) put(id string, lat time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[id] = latencyEntry{latency: lat, at: time.Now()}
}

// fastest returns the server with the lowest cached HTTP latency.
func (c *latencyCache) fastest(servers []model.Server) (model.Server, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var best model.Server
	var bestLat time.Duration
	for _, s := range servers {
		if e, ok := c.m[s.ID]; ok && e.latency > 0 && (bestLat == 0 || e.latency < bestLat) {
			best, bestLat = s, e.latency
		}
	}
	return best, bestLat > 0
}

// annotate fills Server.latency and latency_tested_at.
func (c *latencyCache) annotate(p *berylliumv1.Server) *berylliumv1.Server {
	c.mu.Lock()
	e, ok := c.m[p.GetId()]
	c.mu.Unlock()
	if ok {
		p.LatencyTestedAt = timestamppb.New(e.at)
		if e.latency > 0 {
			p.Latency = durationpb.New(e.latency)
		}
	}
	return p
}

const (
	defaultPingTimeout = 5 * time.Second
	maxPingTimeout     = time.Minute
)

func (s *testService) PingServers(req *berylliumv1.PingServersRequest, stream berylliumv1.TestService_PingServersServer) error {
	var servers []model.Server
	if ids := req.GetServerIds(); len(ids) > 0 {
		for _, id := range ids {
			srv, _, err := s.subs.Server(id)
			if err != nil {
				return subErr(err)
			}
			servers = append(servers, srv)
		}
	} else {
		var err error
		if servers, err = s.subs.Servers(req.GetSubscriptionId()); err != nil {
			return subErr(err)
		}
	}
	timeout := req.GetTimeout().AsDuration()
	switch {
	case req.GetTimeout() == nil:
		timeout = defaultPingTimeout
	case timeout <= 0 || timeout > maxPingTimeout:
		return status.Errorf(codes.InvalidArgument, "timeout must be between 0 and %s", maxPingTimeout)
	}
	method := map[berylliumv1.PingMethod]core.PingMethod{
		berylliumv1.PingMethod_PING_METHOD_TCP:  core.PingTCP,
		berylliumv1.PingMethod_PING_METHOD_ICMP: core.PingICMP,
	}[req.GetMethod()]
	if method == "" {
		method = core.PingHTTP
	}

	ctx := stream.Context()
	results := make(chan core.PingResult)
	go func() {
		s.pinger.Ping(ctx, servers, core.PingOptions{Method: method, URL: req.GetUrl(), Timeout: timeout}, results)
		close(results)
	}()
	var sendErr error
	for r := range results {
		if method == core.PingHTTP {
			s.latency.put(r.ServerID, r.Latency)
		}
		if sendErr != nil {
			continue // drain so Ping can finish
		}
		resp := &berylliumv1.PingServersResponse{ServerId: r.ServerID}
		if r.Err != nil {
			resp.Error = &berylliumv1.ErrorDetail{Reason: berylliumv1.ErrorReason_ERROR_REASON_NETWORK_UNAVAILABLE, Message: r.Err.Error()}
		} else {
			resp.Latency = durationpb.New(r.Latency)
		}
		sendErr = stream.Send(resp)
	}
	return sendErr
}
