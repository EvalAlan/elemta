package commands

import (
	"fmt"
	"os"
	"time"

	"github.com/EvalAlan/elemta/internal/offsite"
	"github.com/spf13/cobra"
)

// elemta backup keeps backups off the server (scripts/backup-offsite.sh runs
// it). Everything comes from BACKUP_* environment variables, which the
// deployment keeps in a root-only env file, so no key is ever on a command
// line.
func init() {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Seal backups with age and keep them in an S3 bucket",
		// Needs no Elemta configuration: only the bucket and the key.
		PersistentPreRun: func(*cobra.Command, []string) {},
		// A failed upload is an error to read in the journal, not a reason
		// to print how to use the command.
		SilenceUsage: true,
	}
	client := func() (*offsite.Client, error) {
		c, err := offsite.ConfigFromEnv()
		if err != nil {
			return nil, err
		}
		return offsite.New(c)
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "upload <backup directory>",
		Short: "Encrypt a backup to BACKUP_AGE_RECIPIENT and upload it as it is encrypted",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			recipient := os.Getenv("BACKUP_AGE_RECIPIENT")
			if recipient == "" {
				return fmt.Errorf("set BACKUP_AGE_RECIPIENT to the age public key backups are encrypted to")
			}
			c, err := client()
			if err != nil {
				return err
			}
			key, size, err := c.SealAndUpload(cmd.Context(), args[0], recipient)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "uploaded %s (%d bytes)\n", key, size)
			return nil
		},
	})

	var daily, weekly int
	var recent time.Duration
	var dryRun bool
	prune := &cobra.Command{
		Use:   "prune",
		Short: "Delete all but the last hours' backups and the newest of each recent day and week",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := client()
			if err != nil {
				return err
			}
			objs, err := c.List(cmd.Context())
			if err != nil {
				return err
			}
			keep, drop := offsite.Prune(objs, recent, daily, weekly)
			out := cmd.OutOrStdout()
			for _, o := range drop {
				if dryRun {
					fmt.Fprintf(out, "would delete %s\n", o.Key)
					continue
				}
				if err := c.Delete(cmd.Context(), o.Key); err != nil {
					return fmt.Errorf("delete %s: %w", o.Key, err)
				}
				fmt.Fprintf(out, "deleted %s\n", o.Key)
			}
			fmt.Fprintf(out, "kept %d backups, %s %d\n", len(keep), map[bool]string{true: "would delete", false: "deleted"}[dryRun], len(drop))
			return nil
		},
	}
	prune.Flags().DurationVar(&recent, "recent", 48*time.Hour, "Keep every backup taken within this long of the newest one")
	prune.Flags().IntVar(&daily, "daily", 14, "Keep the newest backup of each of this many recent days")
	prune.Flags().IntVar(&weekly, "weekly", 8, "Keep the newest backup of each of this many recent weeks")
	prune.Flags().BoolVar(&dryRun, "dry-run", false, "Say what would be deleted without deleting it")
	cmd.AddCommand(prune)

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List the backups in the bucket, newest first",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := client()
			if err != nil {
				return err
			}
			objs, err := c.List(cmd.Context())
			if err != nil {
				return err
			}
			for _, o := range objs {
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %10d  %s\n", o.Taken.Format(time.RFC3339), o.Size, o.Key)
			}
			return nil
		},
	})
	// Cobra doesn't pass SilenceUsage down, so each subcommand gets it.
	for _, sub := range cmd.Commands() {
		sub.SilenceUsage = true
	}
	rootCmd.AddCommand(cmd)
}
