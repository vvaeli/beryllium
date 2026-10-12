package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/spf13/cobra"
	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/client"
	"google.golang.org/protobuf/types/known/durationpb"
)

var pingMethods = map[string]berylliumv1.PingMethod{
	"http": berylliumv1.PingMethod_PING_METHOD_HTTP,
	"tcp":  berylliumv1.PingMethod_PING_METHOD_TCP,
	"icmp": berylliumv1.PingMethod_PING_METHOD_ICMP,
}

func (a *app) pingCmd() *cobra.Command {
	var (
		sub     string
		method  string
		target  string
		timeout time.Duration
	)
	cmd := &cobra.Command{
		Use:   "ping [server...]",
		Short: "Measure server latency",
		Long: "Measure latency of the given servers, of a subscription (--sub) or of all servers.\n\n" +
			"Methods:\n" +
			"  http  GET a test URL through the server over a fresh connection — checks the\n" +
			"        whole chain, the latency includes the proxy handshake (default)\n" +
			"  tcp   TCP handshake to the server, without the proxy (not for UDP protocols)\n" +
			"  icmp  ICMP echo to the server's host",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, ok := pingMethods[method]
			if !ok {
				return fmt.Errorf("unknown method %q (want http, tcp or icmp)", method)
			}
			req := &berylliumv1.PingServersRequest{Method: m, Url: target, Timeout: durationpb.New(timeout)}
			return a.slowCall(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				names := map[string]string{}
				all, err := c.Subscriptions.ListServers(ctx, &berylliumv1.ListServersRequest{})
				if err != nil {
					return err
				}
				for _, s := range all.GetServers() {
					names[s.GetId()] = s.GetName()
				}
				for _, arg := range args {
					srv, err := resolveServer(ctx, c, arg)
					if err != nil {
						return err
					}
					req.ServerIds = append(req.ServerIds, srv.GetId())
				}
				if sub != "" {
					s, err := resolveSub(ctx, c, sub)
					if err != nil {
						return err
					}
					req.SubscriptionId = s.GetId()
				}
				stream, err := c.Test.PingServers(ctx, req)
				if err != nil {
					return err
				}
				var results []*berylliumv1.PingServersResponse
				for {
					r, err := stream.Recv()
					if errors.Is(err, io.EOF) {
						break
					}
					if err != nil {
						return err
					}
					results = append(results, r)
					if !a.json {
						printPing(a.out, r, names[r.GetServerId()])
					}
				}
				if a.json {
					return printProtoList(a, results)
				}
				return summarizePing(a.out, results, names)
			})
		},
	}
	cmd.Flags().StringVar(&sub, "sub", "", "ping servers of this subscription")
	cmd.Flags().StringVar(&method, "method", "http", "http, tcp or icmp")
	cmd.Flags().StringVar(&target, "url", "", "test URL for the http method (default: http://www.gstatic.com/generate_204)")
	cmd.Flags().DurationVar(&timeout, "timeout-per-server", 5*time.Second, "timeout for each server")
	return cmd
}

func printPing(w io.Writer, r *berylliumv1.PingServersResponse, name string) {
	if e := r.GetError(); e != nil {
		fmt.Fprintf(w, "%8s  %s  (%s)\n", "fail", name, e.GetMessage())
		return
	}
	fmt.Fprintf(w, "%5d ms  %s\n", r.GetLatency().AsDuration().Milliseconds(), name)
}

func summarizePing(w io.Writer, results []*berylliumv1.PingServersResponse, names map[string]string) error {
	var ok []*berylliumv1.PingServersResponse
	for _, r := range results {
		if r.GetError() == nil {
			ok = append(ok, r)
		}
	}
	if len(ok) == 0 {
		return fmt.Errorf("no server responded (%d tested)", len(results))
	}
	sort.Slice(ok, func(i, j int) bool { return ok[i].GetLatency().AsDuration() < ok[j].GetLatency().AsDuration() })
	fmt.Fprintf(w, "\n%d/%d responded; fastest: %s (%d ms)\n", len(ok), len(results),
		names[ok[0].GetServerId()], ok[0].GetLatency().AsDuration().Milliseconds())
	return nil
}
