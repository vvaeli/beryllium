package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/client"
	"github.com/vvaeli/beryllium/internal/version"
	"google.golang.org/protobuf/encoding/protojson"
)

func (a *app) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show CLI and daemon versions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var dv *berylliumv1.GetVersionResponse
			err := a.call(cmd.Context(), func(ctx context.Context, c *client.Client) (err error) {
				dv, err = c.Daemon.GetVersion(ctx, &berylliumv1.GetVersionRequest{})
				return err
			})
			// An unreachable daemon is reported, not treated as a failure:
			// the CLI version alone is still useful.
			if a.json {
				return a.printJSON(versionJSON(dv, err))
			}
			fmt.Fprintf(a.out, "%-11s %s\n", "beryl", version.String())
			if err != nil {
				fmt.Fprintf(a.out, "%-11s not reachable: %v\n", "berylliumd", err)
				var ce *client.Error
				if errors.As(err, &ce) && ce.Hint != "" {
					printHint(cmd.ErrOrStderr(), ce.Hint)
				}
				return nil
			}
			fmt.Fprintf(a.out, "%-11s %s (%s, %s) %s/%s\n", "berylliumd",
				dv.GetVersion(), dv.GetCommit(), dv.GetBuildDate(), dv.GetOs(), dv.GetArch())
			for _, core := range dv.GetCores() {
				fmt.Fprintf(a.out, "  %-9s %s\n", core.GetKind(), core.GetVersion())
			}
			return nil
		},
	}
}

func versionJSON(dv *berylliumv1.GetVersionResponse, err error) map[string]any {
	out := map[string]any{
		"cli": map[string]string{"version": version.Version, "commit": version.Commit, "build_date": version.Date},
	}
	if err != nil {
		out["daemon_error"] = err.Error()
		return out
	}
	raw, _ := protojson.MarshalOptions{UseProtoNames: true}.Marshal(dv)
	out["daemon"] = json.RawMessage(raw)
	return out
}

func printHint(w io.Writer, hint string) {
	fmt.Fprintln(w, "hint:", strings.ReplaceAll(hint, "\n", "\n      "))
}
