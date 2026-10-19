package commands

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/EvalAlan/elemta/internal/mailbox"
	"github.com/spf13/cobra"
)

var mailboxCmd = &cobra.Command{
	Use: "mailbox", Short: "Run the durable IMAP and LMTP mailbox service",
	PersistentPreRun: func(_ *cobra.Command, _ []string) {},
	RunE: func(cmd *cobra.Command, _ []string) error {
		path := configPath
		if path == "" {
			path = "config/mailbox.toml"
		}
		cfg, err := mailbox.LoadConfig(path)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		service, err := mailbox.Open(initCtx, cfg, slog.Default())
		if err != nil {
			return err
		}
		defer service.Close()
		return service.Run(ctx)
	},
}

func init() { rootCmd.AddCommand(mailboxCmd) }
