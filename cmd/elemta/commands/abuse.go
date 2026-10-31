package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/EvalAlan/elemta/internal/abuse"
	"github.com/spf13/cobra"
)

// The host's firewall agent (scripts/abuse-firewall.sh) runs as root and these
// run in a container, so the agent treats this output as untrusted input and
// checks every line itself.
func init() {
	cmd := &cobra.Command{Use: "abuse", Short: "Abuse protection for the host's firewall agent", PersistentPreRun: func(_ *cobra.Command, _ []string) {}}
	engine := func(cmd *cobra.Command) (*abuse.Engine, context.Context, context.CancelFunc, error) {
		ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
		e := abuse.New("firewall", os.Getenv("VALKEY_ADDR"), nil)
		if !e.SyncNow(ctx) {
			cancel()
			return nil, nil, nil, errors.New("Valkey is unreachable")
		}
		return e, ctx, cancel, nil
	}
	cmd.AddCommand(&cobra.Command{
		Use: "firewall-plan", Short: "Print what the firewall should hold",
		RunE: func(c *cobra.Command, _ []string) error {
			e, _, cancel, err := engine(c)
			if err != nil {
				return err
			}
			defer cancel()
			plan := e.Plan()
			out := c.OutOrStdout()
			// Startup logging shares stdout, so the agent reads only between
			// these lines, and the end marker shows it got the whole plan.
			fmt.Fprintln(out, "plan-begin")
			fmt.Fprintf(out, "mode %s\n", plan.Mode)
			for _, a := range plan.Allow {
				fmt.Fprintf(out, "allow %s\n", a)
			}
			for _, entry := range plan.Entries {
				fmt.Fprintf(out, "block %s %d\n", entry.Target, entry.Seconds)
			}
			fmt.Fprintln(out, "plan-end")
			return nil
		},
	})
	var report abuse.Enforcer
	reportCmd := &cobra.Command{
		Use: "firewall-report", Short: "Record the firewall agent's state for the console",
		RunE: func(c *cobra.Command, _ []string) error {
			e, ctx, cancel, err := engine(c)
			if err != nil {
				return err
			}
			defer cancel()
			report.Name = "nftables"
			return e.ReportEnforcer(ctx, report)
		},
	}
	reportCmd.Flags().StringVar(&report.Host, "host", "", "Host name")
	reportCmd.Flags().StringVar(&report.Mode, "mode", "", "off, log or apply")
	reportCmd.Flags().IntVar(&report.Entries, "entries", 0, "Addresses the firewall holds, or would hold")
	reportCmd.Flags().Int64Var(&report.Dropped, "dropped", 0, "Packets dropped")
	reportCmd.Flags().StringVar(&report.Error, "error", "", "What went wrong")
	cmd.AddCommand(reportCmd)
	rootCmd.AddCommand(cmd)
}
