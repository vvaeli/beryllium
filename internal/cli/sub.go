package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/client"
	"google.golang.org/protobuf/types/known/durationpb"
)

func (a *app) subCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "sub", Short: "Manage subscriptions"}
	cmd.AddCommand(a.subAddCmd(), a.subListCmd(), a.subRemoveCmd(), a.subSetCmd(), a.subUpdateCmd(), a.subQRCmd())
	return cmd
}

func (a *app) subAddCmd() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "add <url>",
		Short: "Add a subscription by URL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.HasPrefix(strings.TrimSpace(args[0]), "http://") {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: plain http:// is not encrypted; prefer https://")
			}
			var sub *berylliumv1.Subscription
			err := a.slowCall(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				resp, err := c.Subscriptions.AddSubscription(ctx, &berylliumv1.AddSubscriptionRequest{Url: args[0], Name: name})
				sub = resp.GetSubscription()
				return err
			})
			if err != nil {
				return err
			}
			if a.json {
				return a.printProto(sub)
			}
			fmt.Fprintf(a.out, "added %q (%s): %d servers\n", sub.GetName(), sub.GetId(), sub.GetServerCount())
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "display name (default: provider title)")
	return cmd
}

func (a *app) subListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List subscriptions",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			subs, err := a.listSubs(cmd.Context())
			if err != nil {
				return err
			}
			if a.json {
				return printProtoList(a, subs)
			}
			if len(subs) == 0 {
				fmt.Fprintln(a.out, "no subscriptions; add one with: beryl sub add <url>")
				return nil
			}
			w := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tSERVERS\tTRAFFIC\tEXPIRES\tUPDATED\tSTATUS")
			for _, s := range subs {
				st := "ok"
				if s.GetLastError() != "" {
					st = "error: " + s.GetLastError()
				}
				if s.GetKind() == berylliumv1.SubscriptionKind_SUBSCRIPTION_KIND_LOCAL {
					st = "imported"
				}
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\n", s.GetId(), s.GetName(), s.GetServerCount(),
					traffic(s.GetQuota()), expires(s.GetQuota()), ago(s.GetUpdatedAt().AsTime()), st)
			}
			return w.Flush()
		},
	}
}

func (a *app) subRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rm <id|name>",
		Aliases: []string{"remove"},
		Short:   "Remove a subscription",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.call(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				sub, err := resolveSub(ctx, c, args[0])
				if err != nil {
					return err
				}
				if _, err := c.Subscriptions.RemoveSubscription(ctx, &berylliumv1.RemoveSubscriptionRequest{Id: sub.GetId()}); err != nil {
					return err
				}
				fmt.Fprintf(a.out, "removed %q\n", sub.GetName())
				return nil
			})
		},
	}
}

func (a *app) subSetCmd() *cobra.Command {
	var (
		name     string
		interval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "set <id|name>",
		Short: "Rename a subscription or change its auto-update interval",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &berylliumv1.UpdateSubscriptionRequest{}
			if cmd.Flags().Changed("name") {
				req.Name = &name
			}
			if cmd.Flags().Changed("interval") {
				req.AutoUpdateInterval = durationpb.New(interval)
			}
			if req.Name == nil && req.AutoUpdateInterval == nil {
				return fmt.Errorf("nothing to change: pass --name and/or --interval")
			}
			return a.call(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				sub, err := resolveSub(ctx, c, args[0])
				if err != nil {
					return err
				}
				req.Id = sub.GetId()
				resp, err := c.Subscriptions.UpdateSubscription(ctx, req)
				if err != nil {
					return err
				}
				if a.json {
					return a.printProto(resp.GetSubscription())
				}
				fmt.Fprintf(a.out, "%q: auto-update %s\n", resp.GetSubscription().GetName(), every(resp.GetSubscription().GetAutoUpdateInterval().AsDuration()))
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "new display name")
	cmd.Flags().DurationVar(&interval, "interval", 0, "auto-update interval, e.g. 6h; 0 disables")
	return cmd
}

func (a *app) subUpdateCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "update [<id|name>]",
		Short: "Re-download subscriptions now",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if all == (len(args) == 1) {
				return fmt.Errorf("pass a subscription or --all")
			}
			return a.slowCall(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				var subs []*berylliumv1.Subscription
				if all {
					resp, err := c.Subscriptions.RefreshAllSubscriptions(ctx, &berylliumv1.RefreshAllSubscriptionsRequest{})
					if err != nil {
						return err
					}
					subs = resp.GetSubscriptions()
				} else {
					sub, err := resolveSub(ctx, c, args[0])
					if err != nil {
						return err
					}
					resp, err := c.Subscriptions.RefreshSubscription(ctx, &berylliumv1.RefreshSubscriptionRequest{Id: sub.GetId()})
					if err != nil {
						return err
					}
					subs = append(subs, resp.GetSubscription())
				}
				if a.json {
					return printProtoList(a, subs)
				}
				failed := 0
				for _, s := range subs {
					if s.GetKind() == berylliumv1.SubscriptionKind_SUBSCRIPTION_KIND_LOCAL {
						continue
					}
					if e := s.GetLastError(); e != "" {
						failed++
						fmt.Fprintf(a.out, "%s: failed: %s (kept %d servers)\n", s.GetName(), e, s.GetServerCount())
					} else {
						fmt.Fprintf(a.out, "%s: %d servers\n", s.GetName(), s.GetServerCount())
					}
				}
				if failed > 0 {
					return fmt.Errorf("%d subscription(s) failed to update", failed)
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "update all subscriptions")
	return cmd
}

func (a *app) listSubs(ctx context.Context) (subs []*berylliumv1.Subscription, err error) {
	err = a.call(ctx, func(ctx context.Context, c *client.Client) error {
		resp, err := c.Subscriptions.ListSubscriptions(ctx, &berylliumv1.ListSubscriptionsRequest{})
		subs = resp.GetSubscriptions()
		return err
	})
	return subs, err
}

// resolveSub accepts an ID, a unique ID prefix, a name, or a unique part
// of a name.
func resolveSub(ctx context.Context, c *client.Client, arg string) (*berylliumv1.Subscription, error) {
	resp, err := c.Subscriptions.ListSubscriptions(ctx, &berylliumv1.ListSubscriptionsRequest{})
	if err != nil {
		return nil, err
	}
	return resolve(resp.GetSubscriptions(), "subscription", arg,
		func(s *berylliumv1.Subscription) (string, string) { return s.GetId(), s.GetName() })
}

// resolve picks one item by exact ID, then by ID prefix or exact name, then
// by a case-insensitive name substring. Ambiguity at any level is an error.
func resolve[T any](items []T, kind, arg string, key func(T) (id, name string)) (T, error) {
	var strong, weak []T
	lower := strings.ToLower(arg)
	for _, it := range items {
		id, name := key(it)
		switch {
		case id == arg:
			return it, nil
		case strings.HasPrefix(id, arg) || strings.EqualFold(name, arg):
			strong = append(strong, it)
		case strings.Contains(strings.ToLower(name), lower):
			weak = append(weak, it)
		}
	}
	if len(strong) == 0 {
		strong = weak
	}
	return pickOne(strong, kind, arg, func(it T) string { id, name := key(it); return id + " (" + name + ")" })
}

func pickOne[T any](matches []T, kind, arg string, id func(T) string) (T, error) {
	var zero T
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return zero, fmt.Errorf("no %s matches %q", kind, arg)
	default:
		ids := make([]string, len(matches))
		for i, m := range matches {
			ids[i] = id(m)
		}
		return zero, fmt.Errorf("%q matches several %ss: %s", arg, kind, strings.Join(ids, ", "))
	}
}

func traffic(q *berylliumv1.Quota) string {
	if q == nil {
		return "-"
	}
	used := q.GetUploadBytes() + q.GetDownloadBytes()
	if q.GetTotalBytes() == 0 {
		return bytesHuman(used) + " / ∞"
	}
	return bytesHuman(used) + " / " + bytesHuman(q.GetTotalBytes())
}

func expires(q *berylliumv1.Quota) string {
	if q.GetExpiresAt() == nil {
		return "-"
	}
	t := q.GetExpiresAt().AsTime()
	days := int(time.Until(t).Hours() / 24)
	if days < 0 {
		return "expired"
	}
	return fmt.Sprintf("%s (%dd)", t.Local().Format("2006-01-02"), days)
}

func bytesHuman(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func ago(t time.Time) string {
	if t.IsZero() || t.Unix() <= 0 {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func every(d time.Duration) string {
	if d == 0 {
		return "disabled"
	}
	return "every " + strings.TrimSuffix(strings.TrimSuffix(d.String(), "0s"), "0m")
}

// secretWarning goes to stderr so piping the link stays clean.
func secretWarning() {
	fmt.Fprintln(os.Stderr, "warning: this is a secret — anyone with it can use your VPN. Don't post it publicly.")
}
