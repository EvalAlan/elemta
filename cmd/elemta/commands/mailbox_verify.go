package commands

import (
	"fmt"
	"log/slog"

	"github.com/EvalAlan/elemta/internal/mailbox"
	"github.com/spf13/cobra"
)

// Checks a mailbox store after a restore, or periodically: every body a
// message refers to must exist with its recorded checksum.
func init() {
	var sample int
	cmd := &cobra.Command{
		Use: "verify", Short: "Check that every message body exists and matches its checksum",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path := configPath
			if path == "" {
				path = "config/mailbox.toml"
			}
			cfg, err := mailbox.LoadConfig(path)
			if err != nil {
				return err
			}
			service, err := mailbox.Open(cmd.Context(), cfg, slog.Default())
			if err != nil {
				return err
			}
			defer service.Close()
			out := cmd.OutOrStdout()
			r, err := service.Engine().Verify(cmd.Context(), sample, func(n int) { fmt.Fprintf(out, "%d bodies checked\n", n) })
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "checked %d bodies: %d missing, %d corrupt; %d accounts with quota drift\n", r.Checked, len(r.Missing), len(r.Corrupt), len(r.QuotaDrift))
			for _, k := range r.Missing {
				fmt.Fprintf(out, "missing %s\n", k)
			}
			for _, k := range r.Corrupt {
				fmt.Fprintf(out, "corrupt %s\n", k)
			}
			for _, a := range r.QuotaDrift {
				fmt.Fprintf(out, "quota drift %s\n", a)
			}
			if !r.OK() {
				return fmt.Errorf("mailbox store verification failed")
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&sample, "sample", 0, "Check this many random bodies instead of all of them")
	mailboxCmd.AddCommand(cmd)
}
