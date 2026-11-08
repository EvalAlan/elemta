package commands

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/EvalAlan/elemta/internal/mailbox"
	"github.com/spf13/cobra"
)

// Moves one mailbox to another cell (internal/mailbox/move.go): copy,
// place it there in the directory, wait for routers to notice, purge the
// old copy.
func init() {
	var address, toConfig, toCell string
	var settle time.Duration
	var purge bool
	move := &cobra.Command{
		Use:   "move-account",
		Short: "Move one mailbox to another cell, keeping its UIDs, flags and settings",
		Long: `Moves one mailbox from the cell this configuration (-c) serves to the cell
--to-config serves. The mailbox is read-only in its old cell from the start
(deliveries are deferred and retried), copied, checked, placed in --to-cell
in the directory, and, after --settle for routers' caches, purged from the
old cell with --purge. Without --purge the old copy stays, read-only.

The directory account this configuration binds as must be able to write
elemtaMailboxCell. A move that stops part way can be run again.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if address == "" || toConfig == "" || toCell == "" {
				return fmt.Errorf("--address, --to-config and --to-cell are needed")
			}
			src, err := openMailboxService(cmd)
			if err != nil {
				return err
			}
			defer src.Close()
			cfg, err := mailbox.LoadConfig(toConfig)
			if err != nil {
				return err
			}
			dst, err := mailbox.Open(cmd.Context(), cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)))
			if err != nil {
				return fmt.Errorf("destination cell: %w", err)
			}
			defer dst.Close()
			dir, ok := src.Placement()
			if !ok {
				return fmt.Errorf("no directory configured to place the mailbox in")
			}
			out := cmd.OutOrStdout()
			report, err := mailbox.MoveAccount(cmd.Context(), src.Engine(), dst.Engine(), address, func(s string) { fmt.Fprintln(out, s) })
			if err != nil {
				return fmt.Errorf("move: %w (the mailbox is read-only in its old cell until a move completes)", err)
			}
			for table, n := range report.Skipped {
				fmt.Fprintf(out, "left out %d rows of %s: they name accounts in other cells\n", n, table)
			}
			if err := dir.SetCell(cmd.Context(), address, toCell); err != nil {
				return fmt.Errorf("copied, but placing it in %s failed (run again): %w", toCell, err)
			}
			fmt.Fprintf(out, "placed %s in cell %s; waiting %s for routers to notice\n", address, toCell, settle)
			select {
			case <-time.After(settle):
			case <-cmd.Context().Done():
				return cmd.Context().Err()
			}
			if purge {
				res, err := src.Engine().PurgeAccount(cmd.Context(), address)
				if err != nil {
					return fmt.Errorf("moved, but purging the old copy failed: %w", err)
				}
				fmt.Fprintf(out, "purged the old copy (%d messages)\n", res.Messages)
			} else {
				fmt.Fprintln(out, "the old copy stays, read-only; run with --purge, or purge it from the admin console, once you're satisfied")
			}
			b, _ := json.Marshal(report)
			fmt.Fprintln(out, string(b))
			return nil
		},
	}
	f := move.Flags()
	f.StringVar(&address, "address", "", "the mailbox to move")
	f.StringVar(&toConfig, "to-config", "", "the destination cell's mailbox configuration")
	f.StringVar(&toCell, "to-cell", "", "the destination cell's name, as the routers know it")
	f.DurationVar(&settle, "settle", 40*time.Second, "how long to wait for routers' caches (auth.cache_seconds) before purging")
	f.BoolVar(&purge, "purge", false, "purge the old copy once the move is complete")
	mailboxCmd.AddCommand(move)
}
