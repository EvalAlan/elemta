package commands

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/EvalAlan/elemta/internal/mailbox"
	"github.com/spf13/cobra"
)

// For restore drills: checks a mailbox database's recorded body keys against
// a key list, without opening the store or writing anything, so a drill can
// prove a backup's own secrets read its own metadata.
func init() {
	cmd := &cobra.Command{
		Use:   "check-keys",
		Short: "Check that ELEMTA_MAILBOX_BODY_KEYS holds every key the database's store was encrypted with",
		Long: "Reads the database at ELEMTA_MAILBOX_DATABASE_DSN and checks that " +
			"ELEMTA_MAILBOX_BODY_KEYS has a matching key for every body key it has recorded. " +
			"It only reads; restore drills run it on restored metadata with the backup's keys.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			db, err := sql.Open("postgres", os.Getenv("ELEMTA_MAILBOX_DATABASE_DSN"))
			if err != nil {
				return err
			}
			defer func() { _ = db.Close() }()
			if err := mailbox.CheckBodyKeysCover(cmd.Context(), db, os.Getenv("ELEMTA_MAILBOX_BODY_KEYS")); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "body keys cover every key the store recorded")
			return nil
		},
	}
	mailboxCmd.AddCommand(cmd)
}
