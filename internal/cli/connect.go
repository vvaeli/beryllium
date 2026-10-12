package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"
	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/client"
	"github.com/vvaeli/beryllium/internal/core"
	"github.com/vvaeli/beryllium/internal/sysproxy"
)

var coreToProto = map[core.Kind]berylliumv1.CoreKind{
	core.SingBox: berylliumv1.CoreKind_CORE_KIND_SING_BOX,
	core.Xray:    berylliumv1.CoreKind_CORE_KIND_XRAY,
	core.Mihomo:  berylliumv1.CoreKind_CORE_KIND_MIHOMO,
}

func (a *app) connectCmd() *cobra.Command {
	var (
		coreName, modeName, sub string
		auto                    bool
	)
	cmd := &cobra.Command{
		Use:   "connect [server]",
		Short: "Connect to a server, or the fastest one with --auto",
		Long: `Connect to a server (ID, name or part of a name).

Modes (default: the mode from settings, see beryl mode):
  tun     capture all system traffic (needs the daemon running as root)
  proxy   set the OS proxy settings to the local proxy
  local   only run the local HTTP/SOCKS5 proxy; nothing on the system changes

With --auto (or no server) the server with the lowest HTTP latency is
used, measured first if needed; --sub limits the choice to one subscription.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if auto && len(args) > 0 {
				return errors.New("give a server or --auto, not both")
			}
			req := &berylliumv1.ConnectRequest{}
			if modeName != "" {
				m, err := parseMode(modeName)
				if err != nil {
					return err
				}
				req.Mode = m
			}
			if coreName != "" && coreName != "auto" {
				k, err := core.ParseKind(coreName)
				if err != nil {
					return err
				}
				req.Core = coreToProto[k]
			}
			// Auto-select may measure every server first.
			return a.slowCall(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				if len(args) == 1 {
					srv, err := resolveServer(ctx, c, args[0])
					if err != nil {
						return err
					}
					req.ServerId = srv.GetId()
				} else if sub != "" {
					s, err := resolveSub(ctx, c, sub)
					if err != nil {
						return err
					}
					req.SubscriptionId = s.GetId()
				}
				resp, err := c.Connection.Connect(ctx, req)
				if err != nil {
					return err
				}
				sysproxy.Notify()
				return a.printStatus(resp.GetStatus())
			})
		},
	}
	cmd.Flags().StringVar(&coreName, "core", "auto", "core to use: auto, sing-box, xray or mihomo")
	cmd.Flags().StringVar(&modeName, "mode", "", "tun, proxy or local (default: from settings)")
	cmd.Flags().BoolVar(&auto, "auto", false, "pick the server with the lowest latency")
	cmd.Flags().StringVar(&sub, "sub", "", "with --auto: only servers of this subscription")
	return cmd
}

// parseMode accepts the names users type.
func parseMode(s string) (berylliumv1.Mode, error) {
	switch strings.ToLower(s) {
	case "tun", "vpn":
		return berylliumv1.Mode_MODE_TUN, nil
	case "proxy", "system", "system-proxy", "sysproxy":
		return berylliumv1.Mode_MODE_SYSTEM_PROXY, nil
	case "local", "local-proxy":
		return berylliumv1.Mode_MODE_LOCAL_PROXY, nil
	}
	return 0, fmt.Errorf("unknown mode %q (want tun, proxy or local)", s)
}

func modeString(m berylliumv1.Mode) string {
	switch m {
	case berylliumv1.Mode_MODE_TUN:
		return "tun"
	case berylliumv1.Mode_MODE_SYSTEM_PROXY:
		return "proxy"
	case berylliumv1.Mode_MODE_LOCAL_PROXY:
		return "local"
	}
	return "-"
}

func (a *app) disconnectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disconnect",
		Short: "Disconnect",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.call(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				resp, err := c.Connection.Disconnect(ctx, &berylliumv1.DisconnectRequest{})
				if err != nil {
					return err
				}
				sysproxy.Notify()
				return a.printStatus(resp.GetStatus())
			})
		},
	}
}

func (a *app) statusCmd() *cobra.Command {
	var watch bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the connection status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if watch {
				return a.watchStatus(cmd.Context())
			}
			return a.call(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				resp, err := c.Connection.GetStatus(ctx, &berylliumv1.GetStatusRequest{})
				if err != nil {
					return err
				}
				return a.printStatus(resp.GetStatus())
			})
		},
	}
	cmd.Flags().BoolVarP(&watch, "watch", "w", false, "keep printing the status until interrupted")
	return cmd
}

// watchStatus streams status updates until the stream or ctx ends.
func (a *app) watchStatus(ctx context.Context) error {
	c, err := client.New(a.socket)
	if err != nil {
		return err
	}
	defer c.Close()
	stream, err := c.Connection.WatchStatus(ctx, &berylliumv1.WatchStatusRequest{})
	if err != nil {
		return c.Explain(err)
	}
	for {
		resp, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			return c.Explain(err)
		}
		if !a.json {
			fmt.Fprintln(a.out, "---", time.Now().Format("15:04:05"))
		}
		if err := a.printStatus(resp.GetStatus()); err != nil {
			return err
		}
	}
}

func (a *app) testCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test [url]",
		Short: "Check connectivity through the tunnel",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &berylliumv1.UrlTestRequest{}
			if len(args) == 1 {
				req.Url = args[0]
			}
			return a.call(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				resp, err := c.Test.UrlTest(ctx, req)
				if err != nil {
					return err
				}
				if a.json {
					return a.printProto(resp)
				}
				if !resp.GetOk() {
					return fmt.Errorf("test failed: %s", resp.GetError().GetMessage())
				}
				fmt.Fprintf(a.out, "ok, %d ms\n", resp.GetLatency().AsDuration().Milliseconds())
				return nil
			})
		},
	}
}

// coreName shows cores the way users type them (sing-box, xray, mihomo).
func coreName(k berylliumv1.CoreKind) string {
	for name, pk := range coreToProto {
		if pk == k {
			return string(name)
		}
	}
	return "-"
}

func (a *app) printStatus(st *berylliumv1.ConnectionStatus) error {
	if a.json {
		return a.printProto(st)
	}
	state := enumName(st.GetState().String(), "CONNECTION_STATE_")
	fmt.Fprintln(a.out, "state:   ", state)
	if st.GetMode() != berylliumv1.Mode_MODE_UNSPECIFIED {
		fmt.Fprintln(a.out, "mode:    ", modeString(st.GetMode()))
	}
	if srv := st.GetServer(); srv != nil {
		fmt.Fprintf(a.out, "server:   %s (%s)\n", srv.GetName(), enumName(srv.GetProtocol().String(), "PROTOCOL_"))
		fmt.Fprintf(a.out, "core:     %s — %s\n", coreName(st.GetCore()), st.GetCoreReason())
	}
	if p := st.GetLocalProxy(); p != "" {
		fmt.Fprintf(a.out, "proxy:    %s (HTTP and SOCKS5)\n", p)
	}
	if t := st.GetConnectedSince(); t != nil {
		fmt.Fprintf(a.out, "uptime:   %s\n", time.Since(t.AsTime()).Round(time.Second))
	}
	if tr := st.GetTraffic(); tr != nil {
		fmt.Fprintf(a.out, "traffic:  ↑ %s  ↓ %s\n", bytesHuman(tr.GetUploadBytesTotal()), bytesHuman(tr.GetDownloadBytesTotal()))
	}
	if r := st.GetRecovery(); r.GetCount() > 0 {
		fmt.Fprintf(a.out, "recovery: %d", r.GetCount())
		if res := r.GetLastResult(); res != "" {
			trigger := strings.ReplaceAll(strings.ToLower(enumName(r.GetLastTrigger().String(), "RECOVERY_TRIGGER_")), "_", " ")
			fmt.Fprintf(a.out, "; last after %s: %s in %s", trigger, res, r.GetLastDuration().AsDuration().Round(time.Millisecond))
			if at := r.GetLastAt(); at != nil {
				fmt.Fprintf(a.out, " (%s ago)", time.Since(at.AsTime()).Round(time.Second))
			}
		}
		fmt.Fprintln(a.out)
	}
	if e := st.GetError(); e != nil {
		fmt.Fprintln(a.out, "error:   ", e.GetMessage())
	}
	return nil
}
