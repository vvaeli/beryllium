package cli

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/client"
	"github.com/vvaeli/beryllium/internal/sysproxy"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func (a *app) getSettings(ctx context.Context, c *client.Client) (*berylliumv1.Settings, error) {
	resp, err := c.Settings.GetSettings(ctx, &berylliumv1.GetSettingsRequest{})
	return resp.GetSettings(), err
}

func (a *app) updateSettings(ctx context.Context, c *client.Client, s *berylliumv1.Settings, paths ...string) (*berylliumv1.Settings, error) {
	resp, err := c.Settings.UpdateSettings(ctx, &berylliumv1.UpdateSettingsRequest{
		Settings: s, UpdateMask: &fieldmaskpb.FieldMask{Paths: paths}})
	return resp.GetSettings(), err
}

func (a *app) modeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mode [tun|proxy|local]",
		Short: "Show or change the connection mode (applies live when connected)",
		Long: `Show or change the default connection mode. A live connection switches
to the new mode without changing the server.

  tun     capture all system traffic (needs the daemon running as root);
          the only mode that covers every app on Hyprland, niri, sway etc.
  proxy   set the OS proxy settings (macOS, Windows, GNOME, KDE; elsewhere
          only the session environment for apps started afterwards)
  local   only run the local HTTP/SOCKS5 proxy`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.slowCall(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				var (
					s   *berylliumv1.Settings
					err error
				)
				if len(args) == 0 {
					s, err = a.getSettings(ctx, c)
				} else {
					var m berylliumv1.Mode
					if m, err = parseMode(args[0]); err != nil {
						return err
					}
					s, err = a.updateSettings(ctx, c, &berylliumv1.Settings{Mode: m}, "mode")
					sysproxy.Notify()
				}
				if err != nil {
					return err
				}
				if a.json {
					return a.printJSON(map[string]string{"mode": modeString(s.GetMode())})
				}
				fmt.Fprintln(a.out, modeString(s.GetMode()))
				return nil
			})
		},
	}
}

// envCmd prints shell exports for tools that only honor proxy variables.
func (a *app) envCmd() *cobra.Command {
	var (
		shell string
		unset bool
	)
	cmd := &cobra.Command{
		Use:   "env",
		Short: "Print proxy environment variables for the local proxy",
		Long: `Print http_proxy, https_proxy, all_proxy and no_proxy for the running
local proxy, e.g.:

  eval "$(beryl env)"            # bash, zsh
  beryl env --shell fish | source
  beryl env --unset | source     # remove them again`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			vars := map[string]string{}
			if !unset {
				err := a.call(cmd.Context(), func(ctx context.Context, c *client.Client) error {
					resp, err := c.Connection.GetStatus(ctx, &berylliumv1.GetStatusRequest{})
					if err != nil {
						return err
					}
					p := resp.GetStatus().GetLocalProxy()
					if p == "" {
						return errors.New("not connected")
					}
					vars["http_proxy"], vars["https_proxy"] = "http://"+p, "http://"+p
					vars["all_proxy"] = "socks5h://" + p
					vars["no_proxy"] = strings.Join(sysproxy.DefaultBypass, ",")
					return nil
				})
				if err != nil {
					return err
				}
			}
			for _, k := range []string{"http_proxy", "https_proxy", "all_proxy", "no_proxy"} {
				for _, name := range []string{k, strings.ToUpper(k)} {
					switch {
					case unset && shell == "fish":
						fmt.Fprintf(a.out, "set -e %s\n", name)
					case unset:
						fmt.Fprintf(a.out, "unset %s\n", name)
					case shell == "fish":
						fmt.Fprintf(a.out, "set -gx %s %s\n", name, strconv.Quote(vars[k]))
					default:
						fmt.Fprintf(a.out, "export %s=%s\n", name, strconv.Quote(vars[k]))
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&shell, "shell", "sh", "sh (bash, zsh) or fish")
	cmd.Flags().BoolVar(&unset, "unset", false, "print commands that remove the variables")
	return cmd
}

var matchNames = map[string]berylliumv1.RuleMatch{
	"domain":         berylliumv1.RuleMatch_RULE_MATCH_DOMAIN,
	"domain-suffix":  berylliumv1.RuleMatch_RULE_MATCH_DOMAIN_SUFFIX,
	"suffix":         berylliumv1.RuleMatch_RULE_MATCH_DOMAIN_SUFFIX,
	"domain-keyword": berylliumv1.RuleMatch_RULE_MATCH_DOMAIN_KEYWORD,
	"keyword":        berylliumv1.RuleMatch_RULE_MATCH_DOMAIN_KEYWORD,
	"ip":             berylliumv1.RuleMatch_RULE_MATCH_IP_CIDR,
	"ip-cidr":        berylliumv1.RuleMatch_RULE_MATCH_IP_CIDR,
	"process":        berylliumv1.RuleMatch_RULE_MATCH_PROCESS_NAME,
	"process-name":   berylliumv1.RuleMatch_RULE_MATCH_PROCESS_NAME,
	"process-path":   berylliumv1.RuleMatch_RULE_MATCH_PROCESS_PATH,
}

var actionNames = map[string]berylliumv1.RuleAction{
	"proxy":  berylliumv1.RuleAction_RULE_ACTION_PROXY,
	"direct": berylliumv1.RuleAction_RULE_ACTION_DIRECT,
	"block":  berylliumv1.RuleAction_RULE_ACTION_BLOCK,
}

func matchString(m berylliumv1.RuleMatch) string {
	return strings.ReplaceAll(enumName(m.String(), "RULE_MATCH_"), "_", "-")
}

func (a *app) rulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage your own routing rules (applied before the routing profile)",
		Long: `Your own rules are checked in order before the active routing profile.

  beryl rules add suffix example.com direct
  beryl rules add ip 10.0.0.0/8 direct
  beryl rules add process Telegram proxy      # app-based split tunneling (TUN)
  beryl rules rm 2

Matchers: domain, suffix, keyword, ip, process, process-path.
Actions: proxy, direct, block.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return a.listRules(cmd.Context()) },
	}
	add := &cobra.Command{
		Use:   "add <match> <value> <proxy|direct|block>",
		Short: "Append a rule",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			m, ok := matchNames[strings.ToLower(args[0])]
			if !ok {
				return fmt.Errorf("unknown matcher %q (want domain, suffix, keyword, ip, process or process-path)", args[0])
			}
			act, ok := actionNames[strings.ToLower(args[2])]
			if !ok {
				return fmt.Errorf("unknown action %q (want proxy, direct or block)", args[2])
			}
			return a.editRules(cmd.Context(), func(rules []*berylliumv1.RoutingRule) ([]*berylliumv1.RoutingRule, error) {
				return append(rules, &berylliumv1.RoutingRule{Match: m, Value: args[1], Action: act}), nil
			})
		},
	}
	rm := &cobra.Command{
		Use:   "rm <number>",
		Short: "Remove a rule by its number in `beryl rules`",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("%q is not a rule number", args[0])
			}
			return a.editRules(cmd.Context(), func(rules []*berylliumv1.RoutingRule) ([]*berylliumv1.RoutingRule, error) {
				if n < 1 || n > len(rules) {
					return nil, fmt.Errorf("there is no rule %d", n)
				}
				return append(rules[:n-1], rules[n:]...), nil
			})
		},
	}
	cmd.AddCommand(&cobra.Command{
		Use: "ls", Short: "List rules", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return a.listRules(cmd.Context()) },
	}, add, rm)
	return cmd
}

func (a *app) listRules(ctx context.Context) error {
	return a.call(ctx, func(ctx context.Context, c *client.Client) error {
		s, err := a.getSettings(ctx, c)
		if err != nil {
			return err
		}
		return a.printRules(s.GetRouting().GetRules())
	})
}

func (a *app) printRules(rules []*berylliumv1.RoutingRule) error {
	if a.json {
		return printProtoList(a, rules)
	}
	if len(rules) == 0 {
		fmt.Fprintln(a.out, "no rules; add one with `beryl rules add`")
		return nil
	}
	w := tabwriter.NewWriter(a.out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "#\tMATCH\tVALUE\tACTION")
	for i, r := range rules {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", i+1, matchString(r.GetMatch()), r.GetValue(), enumName(r.GetAction().String(), "RULE_ACTION_"))
	}
	return w.Flush()
}

func (a *app) editRules(ctx context.Context, edit func([]*berylliumv1.RoutingRule) ([]*berylliumv1.RoutingRule, error)) error {
	return a.slowCall(ctx, func(ctx context.Context, c *client.Client) error {
		s, err := a.getSettings(ctx, c)
		if err != nil {
			return err
		}
		rules, err := edit(s.GetRouting().GetRules())
		if err != nil {
			return err
		}
		s, err = a.updateSettings(ctx, c, &berylliumv1.Settings{Routing: &berylliumv1.RoutingSettings{Rules: rules}}, "routing.rules")
		if err != nil {
			return err
		}
		return a.printRules(s.GetRouting().GetRules())
	})
}

func (a *app) dnsCmd() *cobra.Command {
	var remote, direct, fakeIP, ipv6, providerRouting string
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "Show or change DNS settings",
		Long: `Show or change DNS settings. Empty resolvers use the routing profile's,
then the defaults (remote: DoH 1.1.1.1 through the tunnel; direct: the
system resolver).

  beryl dns --remote https://dns.google/dns-query --direct 77.88.8.8
  beryl dns --ipv6 block      # drop IPv6 so nothing leaks (default)
  beryl dns --fakeip on       # TUN only; faster, may break some apps`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := cmd.Flags()
			upd := &berylliumv1.Settings{Dns: &berylliumv1.DnsSettings{}, Routing: &berylliumv1.RoutingSettings{}}
			var paths []string
			if f.Changed("remote") {
				upd.Dns.RemoteDns, paths = remote, append(paths, "dns.remote_dns")
			}
			if f.Changed("direct") {
				upd.Dns.DirectDns, paths = direct, append(paths, "dns.direct_dns")
			}
			if f.Changed("fakeip") {
				on, err := parseOnOff(fakeIP)
				if err != nil {
					return err
				}
				upd.Dns.FakeIp, paths = on, append(paths, "dns.fake_ip")
			}
			if f.Changed("ipv6") {
				switch ipv6 {
				case "tunnel":
					upd.Dns.Ipv6 = berylliumv1.Ipv6Mode_IPV6_MODE_TUNNEL
				case "block":
					upd.Dns.Ipv6 = berylliumv1.Ipv6Mode_IPV6_MODE_BLOCK
				default:
					return fmt.Errorf("--ipv6 must be tunnel or block")
				}
				paths = append(paths, "dns.ipv6")
			}
			if f.Changed("provider-routing") {
				on, err := parseOnOff(providerRouting)
				if err != nil {
					return err
				}
				upd.Routing.ApplyProviderRouting, paths = on, append(paths, "routing.apply_provider_routing")
			}
			return a.slowCall(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				var (
					s   *berylliumv1.Settings
					err error
				)
				if len(paths) == 0 {
					s, err = a.getSettings(ctx, c)
				} else {
					s, err = a.updateSettings(ctx, c, upd, paths...)
				}
				if err != nil {
					return err
				}
				if a.json {
					return a.printProto(s.GetDns())
				}
				d := s.GetDns()
				fmt.Fprintf(a.out, "remote:   %s\n", orDash(d.GetRemoteDns(), "profile / https://1.1.1.1/dns-query"))
				fmt.Fprintf(a.out, "direct:   %s\n", orDash(d.GetDirectDns(), "profile / system resolver"))
				fmt.Fprintf(a.out, "fakeip:   %s\n", onOff(d.GetFakeIp()))
				fmt.Fprintf(a.out, "ipv6:     %s\n", strings.ToLower(enumName(d.GetIpv6().String(), "IPV6_MODE_")))
				fmt.Fprintf(a.out, "provider routing: %s\n", onOff(s.GetRouting().GetApplyProviderRouting()))
				return nil
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&remote, "remote", "", "resolver for proxied domains (DoH URL, tls://, udp:// or IP; empty = default)")
	f.StringVar(&direct, "direct", "", "resolver for direct domains (empty = system)")
	f.StringVar(&fakeIP, "fakeip", "", "on or off")
	f.StringVar(&ipv6, "ipv6", "", "tunnel or block")
	f.StringVar(&providerRouting, "provider-routing", "", "on or off: apply routing profiles sent by subscriptions")
	return cmd
}

func parseOnOff(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "on", "true", "yes", "1":
		return true, nil
	case "off", "false", "no", "0":
		return false, nil
	}
	return false, fmt.Errorf("%q: want on or off", s)
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func orDash(s, def string) string {
	if s == "" {
		return "(" + def + ")"
	}
	return s
}
