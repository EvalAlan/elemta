package commands

import (
	"fmt"
	"log/slog"

	"github.com/EvalAlan/elemta/internal/mailbox"
	"github.com/spf13/cobra"
)

// Brings stored message bodies onto the current key: those written before
// encryption was turned on, and after a rotation those on older keys. New mail
// is encrypted anyway; this is for what is already there.
func init() {
	cmd := &cobra.Command{
		Use: "encrypt-bodies", Short: "Encrypt stored message bodies with the current key",
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
			r, err := service.Engine().EncryptBodies(cmd.Context(), func(n int) { fmt.Fprintf(out, "%d bodies checked\n", n) })
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "checked %d bodies: %d encrypted, %d failed\n", r.Checked, r.Encrypted, len(r.Failed))
			for _, f := range r.Failed {
				fmt.Fprintf(out, "failed %s\n", f)
			}
			if len(r.Failed) > 0 {
				return fmt.Errorf("%d bodies were left as they were", len(r.Failed))
			}
			return nil
		},
	}
	mailboxCmd.AddCommand(cmd)
}
