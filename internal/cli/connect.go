package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/client"
	"github.com/vvaeli/beryllium/internal/core"
)

var coreToProto = map[core.Kind]berylliumv1.CoreKind{
	core.SingBox: berylliumv1.CoreKind_CORE_KIND_SING_BOX,
	core.Xray:    berylliumv1.CoreKind_CORE_KIND_XRAY,
	core.Mihomo:  berylliumv1.CoreKind_CORE_KIND_MIHOMO,
}

func (a *app) connectCmd() *cobra.Command {
	var coreName string
	cmd := &cobra.Command{
		Use:   "connect <server>",
		Short: "Connect to a server (local HTTP/SOCKS5 proxy for now)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &berylliumv1.ConnectRequest{Mode: berylliumv1.Mode_MODE_LOCAL_PROXY}
			if coreName != "" && coreName != "auto" {
				k, err := core.ParseKind(coreName)
				if err != nil {
					return err
				}
				req.Core = coreToProto[k]
			}
			return a.call(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				srv, err := resolveServer(ctx, c, args[0])
				if err != nil {
					return err
				}
				req.ServerId = srv.GetId()
				resp, err := c.Connection.Connect(ctx, req)
				if err != nil {
					return err
				}
				return a.printStatus(resp.GetStatus())
			})
		},
	}
	cmd.Flags().StringVar(&coreName, "core", "auto", "core to use: auto, sing-box, xray or mihomo")
	return cmd
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
				return a.printStatus(resp.GetStatus())
			})
		},
	}
}

func (a *app) statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the connection status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.call(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				resp, err := c.Connection.GetStatus(ctx, &berylliumv1.GetStatusRequest{})
				if err != nil {
					return err
				}
				return a.printStatus(resp.GetStatus())
			})
		},
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
	if n := st.GetRecovery().GetCount(); n > 0 {
		fmt.Fprintf(a.out, "restarts: %d\n", n)
	}
	if e := st.GetError(); e != nil {
		fmt.Fprintln(a.out, "error:   ", e.GetMessage())
	}
	return nil
}
