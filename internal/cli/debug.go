package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/client"
)

var simulatedEvents = map[string]berylliumv1.SimulatedEvent{
	"sleep":     berylliumv1.SimulatedEvent_SIMULATED_EVENT_SLEEP,
	"wake":      berylliumv1.SimulatedEvent_SIMULATED_EVENT_WAKE,
	"netchange": berylliumv1.SimulatedEvent_SIMULATED_EVENT_NETWORK_CHANGE,
	"check":     berylliumv1.SimulatedEvent_SIMULATED_EVENT_HEALTH_CHECK,
}

func (a *app) debugCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "debug",
		Short:  "Debugging tools",
		Hidden: true,
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "simulate <sleep|wake|netchange|check>",
		Short: "Run the watchdog's handling of an event without it happening",
		Long: `Runs what the daemon does on sleep, wake, a network change or a periodic
health check, then prints the status. A second wake within 15 seconds is
treated as the same wake.`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"sleep", "wake", "netchange", "check"},
		RunE: func(cmd *cobra.Command, args []string) error {
			ev, ok := simulatedEvents[args[0]]
			if !ok {
				return fmt.Errorf("unknown event %q: use sleep, wake, netchange or check", args[0])
			}
			return a.slowCall(cmd.Context(), func(ctx context.Context, c *client.Client) error {
				if _, err := c.Daemon.SimulateEvent(ctx, &berylliumv1.SimulateEventRequest{Event: ev}); err != nil {
					return err
				}
				resp, err := c.Connection.GetStatus(ctx, &berylliumv1.GetStatusRequest{})
				if err != nil {
					return err
				}
				return a.printStatus(resp.GetStatus())
			})
		},
	})
	return cmd
}
