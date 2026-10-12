package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/client"
)

func (a *app) serversCmd() *cobra.Command {
	var sortBy string
	cmd := &cobra.Command{
		Use:   "servers [<subscription>]",
		Short: "List servers of all or one subscription",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.call(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				req := &berylliumv1.ListServersRequest{}
				if len(args) == 1 {
					sub, err := resolveSub(ctx, c, args[0])
					if err != nil {
						return err
					}
					req.SubscriptionId = sub.GetId()
				}
				resp, err := c.Subscriptions.ListServers(ctx, req)
				if err != nil {
					return err
				}
				servers := resp.GetServers()
				switch sortBy {
				case "", "none":
				case "latency":
					// Measured first by latency, then failed, then untested.
					rank := func(s *berylliumv1.Server) (int, time.Duration) {
						switch {
						case s.GetLatency() != nil:
							return 0, s.GetLatency().AsDuration()
						case s.GetLatencyTestedAt() != nil:
							return 1, 0
						}
						return 2, 0
					}
					sort.SliceStable(servers, func(i, j int) bool {
						ri, li := rank(servers[i])
						rj, lj := rank(servers[j])
						return ri < rj || (ri == rj && li < lj)
					})
				case "name":
					sort.SliceStable(servers, func(i, j int) bool { return servers[i].GetName() < servers[j].GetName() })
				default:
					return fmt.Errorf("unknown sort %q (want latency or name)", sortBy)
				}
				if a.json {
					return printProtoList(a, servers)
				}
				if len(servers) == 0 {
					fmt.Fprintln(a.out, "no servers; add a subscription with: beryl sub add <url>")
					return nil
				}
				w := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "ID\tNAME\tPROTOCOL\tTRANSPORT\tSECURITY\tADDRESS\tCOUNTRY\tLATENCY")
				for _, s := range servers {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s:%d\t%s\t%s\n", s.GetId(), s.GetName(),
						enumName(s.GetProtocol().String(), "PROTOCOL_"), enumName(s.GetTransport().String(), "TRANSPORT_"),
						enumName(s.GetSecurity().String(), "SECURITY_"), s.GetAddress(), s.GetPort(), dash(s.GetCountryCode()),
						latency(s))
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().StringVar(&sortBy, "sort", "", "sort by: latency (last `beryl ping` HTTP test), name")
	return cmd
}

func latency(s *berylliumv1.Server) string {
	switch {
	case s.GetLatency() != nil:
		return fmt.Sprintf("%d ms", s.GetLatency().AsDuration().Milliseconds())
	case s.GetLatencyTestedAt() != nil:
		return "fail"
	}
	return "-"
}

func (a *app) importCmd() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "import <file|link>",
		Short: "Import a config file (.conf, .json, .yaml) or a single share link",
		Long: "Import a standalone config as a local subscription: a WireGuard/AmneziaWG .conf,\n" +
			"a sing-box/Xray JSON or Clash YAML file, or a link such as vless://, hy2://, awg://, vpn://.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &berylliumv1.ImportConfigRequest{Name: name}
			if strings.Contains(args[0], "://") {
				req.Source = &berylliumv1.ImportConfigRequest_Uri{Uri: args[0]}
			} else {
				data, err := os.ReadFile(args[0])
				if err != nil {
					return err
				}
				req.Source = &berylliumv1.ImportConfigRequest_FileContent{FileContent: data}
				req.FileName = filepath.Base(args[0])
			}
			return a.call(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				resp, err := c.Subscriptions.ImportConfig(ctx, req)
				if err != nil {
					return err
				}
				if a.json {
					return a.printProto(resp.GetSubscription())
				}
				s := resp.GetSubscription()
				fmt.Fprintf(a.out, "imported %q (%s): %d servers\n", s.GetName(), s.GetId(), s.GetServerCount())
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "display name")
	return cmd
}

// resolveServer accepts the same forms as resolveSub.
func resolveServer(ctx context.Context, c *client.Client, arg string) (*berylliumv1.Server, error) {
	resp, err := c.Subscriptions.ListServers(ctx, &berylliumv1.ListServersRequest{})
	if err != nil {
		return nil, err
	}
	return resolve(resp.GetServers(), "server", arg,
		func(s *berylliumv1.Server) (string, string) { return s.GetId(), s.GetName() })
}

func enumName(s, prefix string) string {
	s = strings.ToLower(strings.TrimPrefix(s, prefix))
	if s == "unspecified" {
		return "-"
	}
	return s
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
