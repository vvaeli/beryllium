package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/client"
)

func (a *app) routingCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "routing",
		Short: "Manage routing profiles (Happ/INCY format)",
		Long: `Routing profiles decide what goes through the proxy, direct or is blocked.
Builtin presets: "Proxy everything", "Russia direct", "Only blocked in
Russia". Providers can send profiles with the subscription; you can import
happ://routing/..., incy://routing/... links, JSON files or https:// URLs.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return a.listProfiles(cmd.Context()) },
	}
	var noActivate bool
	imp := &cobra.Command{
		Use:   "import <link|file|url|->",
		Short: "Import a profile (activated per the link: onadd now, add after geo download)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &berylliumv1.ImportRoutingProfileRequest{}
			switch src := args[0]; {
			case src == "-":
				raw, err := io.ReadAll(cmd.InOrStdin())
				if err != nil {
					return err
				}
				setSource(req, string(raw))
			case strings.Contains(src, "://") || strings.HasPrefix(src, "{"):
				setSource(req, src)
			default:
				raw, err := os.ReadFile(src)
				if err != nil {
					return err
				}
				setSource(req, string(raw))
			}
			if noActivate {
				f := false
				req.Activate = &f
			}
			return a.slowCall(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				resp, err := c.Routing.ImportRoutingProfile(ctx, req)
				if err != nil {
					return err
				}
				return a.printProfile(resp.GetProfile())
			})
		},
	}
	imp.Flags().BoolVar(&noActivate, "no-activate", false, "only import, keep the current profile active")

	use := &cobra.Command{
		Use:   "use <id|name>",
		Short: "Activate a profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.slowCall(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				p, err := resolveProfile(ctx, c, args[0])
				if err != nil {
					return err
				}
				resp, err := c.Routing.ActivateRoutingProfile(ctx, &berylliumv1.ActivateRoutingProfileRequest{Id: p.GetId()})
				if err != nil {
					return err
				}
				return a.printProfile(resp.GetProfile())
			})
		},
	}
	rm := &cobra.Command{
		Use:   "rm <id|name>",
		Short: "Remove an imported or provider profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.call(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				p, err := resolveProfile(ctx, c, args[0])
				if err != nil {
					return err
				}
				if _, err := c.Routing.RemoveRoutingProfile(ctx, &berylliumv1.RemoveRoutingProfileRequest{Id: p.GetId()}); err != nil {
					return err
				}
				if !a.json {
					fmt.Fprintf(a.out, "removed %s\n", p.GetName())
				}
				return nil
			})
		},
	}
	geo := &cobra.Command{
		Use:   "update-geo [id|name]",
		Short: "Re-download geoip/geosite files (default: the active profile)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Geo files can take minutes on slow links (INCY uses 3 min).
			if !a.timeoutSet {
				saved := a.timeout
				a.timeout = 4 * slowTimeout
				defer func() { a.timeout = saved }()
			}
			return a.call(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				var (
					p   *berylliumv1.RoutingProfile
					err error
				)
				if len(args) == 1 {
					p, err = resolveProfile(ctx, c, args[0])
				} else {
					p, err = activeProfile(ctx, c)
				}
				if err != nil {
					return err
				}
				resp, err := c.Routing.RefreshGeoData(ctx, &berylliumv1.RefreshGeoDataRequest{Id: p.GetId()})
				if err != nil {
					return err
				}
				return a.printProfile(resp.GetProfile())
			})
		},
	}
	var (
		qr  bool
		png string
	)
	share := &cobra.Command{
		Use:   "share <id|name>",
		Short: "Print a profile as a happ://routing/onadd/ link (or QR code)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var uri string
			err := a.call(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				p, err := resolveProfile(ctx, c, args[0])
				if err != nil {
					return err
				}
				resp, err := c.Subscriptions.GetShareLink(ctx, &berylliumv1.GetShareLinkRequest{
					Target: &berylliumv1.GetShareLinkRequest_RoutingProfileId{RoutingProfileId: p.GetId()}})
				uri = resp.GetUri()
				return err
			})
			if err != nil {
				return err
			}
			return a.emitSecret(cmd.ErrOrStderr(), uri, qr, png)
		},
	}
	share.Flags().BoolVar(&qr, "qr", false, "show a QR code instead of the link")
	share.Flags().StringVar(&png, "png", "", "write the QR code to a PNG file")

	cmd.AddCommand(&cobra.Command{
		Use: "ls", Short: "List profiles", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return a.listProfiles(cmd.Context()) },
	}, imp, use, rm, geo, share)
	return cmd
}

func setSource(req *berylliumv1.ImportRoutingProfileRequest, s string) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "{") {
		req.Source = &berylliumv1.ImportRoutingProfileRequest_Json{Json: s}
	} else {
		req.Source = &berylliumv1.ImportRoutingProfileRequest_Uri{Uri: s}
	}
}

func (a *app) listProfiles(ctx context.Context) error {
	return a.call(ctx, func(ctx context.Context, c *client.Client) error {
		resp, err := c.Routing.ListRoutingProfiles(ctx, &berylliumv1.ListRoutingProfilesRequest{})
		if err != nil {
			return err
		}
		if a.json {
			return printProtoList(a, resp.GetProfiles())
		}
		w := tabwriter.NewWriter(a.out, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "\tID\tNAME\tSOURCE\tUNMATCHED\tRULES d/p/b\tGEO")
		for _, p := range resp.GetProfiles() {
			mark := ""
			if p.GetActive() {
				mark = "*"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d/%d/%d\t%s\n", mark, p.GetId(), p.GetName(),
				strings.ToLower(enumName(p.GetSource().String(), "ROUTING_PROFILE_SOURCE_")), unmatched(p),
				p.GetDirectRuleCount(), p.GetProxyRuleCount(), p.GetBlockRuleCount(), geoState(p))
		}
		return w.Flush()
	})
}

func (a *app) printProfile(p *berylliumv1.RoutingProfile) error {
	if a.json {
		return a.printProto(p)
	}
	state := "imported"
	if p.GetActive() {
		state = "active"
	} else if p.GetGeoDataState() == berylliumv1.GeoDataState_GEO_DATA_STATE_DOWNLOADING {
		state = "downloading geo files"
	}
	fmt.Fprintf(a.out, "%s (%s): %s; unmatched traffic: %s; geo: %s\n", p.GetName(), p.GetId(), state, unmatched(p), geoState(p))
	if e := p.GetLastError(); e != "" {
		fmt.Fprintln(a.out, "error:", e)
	}
	return nil
}

func unmatched(p *berylliumv1.RoutingProfile) string {
	if p.GetGlobalProxy() {
		return "proxy"
	}
	return "direct"
}

func geoState(p *berylliumv1.RoutingProfile) string {
	s := strings.ToLower(strings.ReplaceAll(enumName(p.GetGeoDataState().String(), "GEO_DATA_STATE_"), "_", " "))
	if p.GetLastError() != "" && p.GetGeoDataState() != berylliumv1.GeoDataState_GEO_DATA_STATE_FAILED {
		s += " (last update failed)"
	}
	return s
}

func resolveProfile(ctx context.Context, c *client.Client, arg string) (*berylliumv1.RoutingProfile, error) {
	resp, err := c.Routing.ListRoutingProfiles(ctx, &berylliumv1.ListRoutingProfilesRequest{})
	if err != nil {
		return nil, err
	}
	return resolve(resp.GetProfiles(), "routing profile", arg,
		func(p *berylliumv1.RoutingProfile) (string, string) { return p.GetId(), p.GetName() })
}

func activeProfile(ctx context.Context, c *client.Client) (*berylliumv1.RoutingProfile, error) {
	resp, err := c.Routing.ListRoutingProfiles(ctx, &berylliumv1.ListRoutingProfilesRequest{})
	if err != nil {
		return nil, err
	}
	for _, p := range resp.GetProfiles() {
		if p.GetActive() {
			return p, nil
		}
	}
	return nil, fmt.Errorf("no active routing profile")
}
