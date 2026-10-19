package commands

import (
	"fmt"
	"log/slog"

	"github.com/EvalAlan/elemta/internal/mailbox"
	"github.com/spf13/cobra"
)

// The running service backfills summaries in small batches; this command
// does all of it at once, for example right after an import or upgrade.
func init() {
	var batch int
	cmd := &cobra.Command{
		Use: "backfill", Short: "Compute message summaries for mail stored without one",
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
			total := 0
			for {
				n, err := service.Engine().Backfill(cmd.Context(), batch)
				total += n
				if err != nil {
					return fmt.Errorf("after %d summaries: %w", total, err)
				}
				if n == 0 {
					break
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%d summaries\n", total)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "done: %d summaries computed\n", total)
			return nil
		},
	}
	cmd.Flags().IntVar(&batch, "batch", 500, "Summaries per database round")
	mailboxCmd.AddCommand(cmd)
}
