package commands

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/EvalAlan/elemta/internal/mailbox"
	"github.com/spf13/cobra"
)

// The cell router: one front door for mailboxes split across cells
// (internal/mailbox/cells.go, router.go).
var mailboxRouterCmd = &cobra.Command{
	Use:              "mailbox-router",
	Short:            "Route mailbox connections (IMAP, POP3, ManageSieve, LMTP, HTTP) to the cell holding each mailbox",
	PersistentPreRun: func(_ *cobra.Command, _ []string) {},
	RunE: func(cmd *cobra.Command, _ []string) error {
		path := configPath
		if path == "" {
			path = "config/mailbox-router.toml"
		}
		cfg, err := mailbox.LoadRouterConfig(path)
		if err != nil {
			return err
		}
		router, err := mailbox.NewRouter(cfg, slog.Default())
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return router.Run(ctx)
	},
}

func init() { rootCmd.AddCommand(mailboxRouterCmd) }
