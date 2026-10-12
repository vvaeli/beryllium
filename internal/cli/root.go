// Package cli implements the beryl command line. The TUI (ROADMAP phase 8)
// will be started from here when beryl runs without a subcommand.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vvaeli/beryllium/internal/client"
	"github.com/vvaeli/beryllium/internal/paths"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// SocketEnv overrides the default daemon address.
const SocketEnv = "BERYLLIUM_SOCKET"

type app struct {
	socket  string
	json    bool
	timeout time.Duration
	out     io.Writer
	// timeoutSet is true when --timeout was given explicitly.
	timeoutSet bool
}

// slowTimeout applies to commands that download subscriptions (with
// retries) unless --timeout is given.
const slowTimeout = 2 * time.Minute

// Execute runs beryl with os.Args and returns the process exit code.
func Execute() int {
	return Run(os.Args[1:], os.Stdout, os.Stderr)
}

// Run executes beryl with args, printing errors and hints to errOut.
func Run(args []string, out, errOut io.Writer) int {
	root := newRoot(out)
	root.SetArgs(args)
	root.SetOut(out)
	root.SetErr(errOut)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(errOut, "beryl:", err)
		var ce *client.Error
		if errors.As(err, &ce) && ce.Hint != "" {
			printHint(errOut, ce.Hint)
		}
		return 1
	}
	return 0
}

func newRoot(out io.Writer) *cobra.Command {
	a := &app{out: out}
	socket := paths.Default().Socket
	if s := os.Getenv(SocketEnv); s != "" {
		socket = s
	}
	root := &cobra.Command{
		Use:           "beryl",
		Short:         "Beryllium proxy/VPN client",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			a.timeoutSet = cmd.Flags().Changed("timeout")
		},
	}
	f := root.PersistentFlags()
	f.StringVar(&a.socket, "socket", socket, "daemon socket or pipe (env "+SocketEnv+")")
	f.BoolVar(&a.json, "json", false, "machine-readable JSON output")
	f.DurationVar(&a.timeout, "timeout", 10*time.Second, "timeout for daemon requests")

	root.AddCommand(a.versionCmd(), a.subCmd(), a.serversCmd(), a.importCmd(), a.shareCmd(),
		a.connectCmd(), a.disconnectCmd(), a.statusCmd(), a.testCmd(), a.pingCmd())
	return root
}

// call connects to the daemon, runs fn with a timeout and explains failures.
func (a *app) call(ctx context.Context, fn func(context.Context, *client.Client) error) error {
	c, err := client.New(a.socket)
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	return c.Explain(fn(ctx, c))
}

// slowCall is call with a longer default timeout for network operations.
func (a *app) slowCall(ctx context.Context, fn func(context.Context, *client.Client) error) error {
	if !a.timeoutSet {
		saved := a.timeout
		a.timeout = slowTimeout
		defer func() { a.timeout = saved }()
	}
	return a.call(ctx, fn)
}

func (a *app) printProto(m proto.Message) error {
	raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(m)
	if err != nil {
		return err
	}
	return a.printJSON(json.RawMessage(raw))
}

func printProtoList[T proto.Message](a *app, list []T) error {
	out := make([]json.RawMessage, 0, len(list))
	for _, m := range list {
		raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(m)
		if err != nil {
			return err
		}
		out = append(out, raw)
	}
	return a.printJSON(out)
}

func (a *app) printJSON(v any) error {
	enc := json.NewEncoder(a.out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
