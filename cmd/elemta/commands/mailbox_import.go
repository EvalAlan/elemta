package commands

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/EvalAlan/elemta/internal/mailbox"
	"github.com/spf13/cobra"
)

func init() {
	var snapshot string
	var offline bool
	cmd := &cobra.Command{
		Use: "import", Short: "Import and verify an offline mailbox snapshot, preserving UIDs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !offline || snapshot == "" {
				return fmt.Errorf("--offline and --snapshot are required; stop all mailbox readers and writers first")
			}
			path := configPath
			if path == "" {
				path = "config/mailbox.toml"
			}
			cfg, err := mailbox.LoadConfig(path)
			if err != nil {
				return err
			}
			root, err := os.OpenRoot(snapshot)
			if err != nil {
				return err
			}
			defer root.Close()
			manifest, err := mailbox.ReadImportSnapshot(root)
			if err != nil {
				return err
			}
			service, err := mailbox.Open(cmd.Context(), cfg, slog.Default())
			if err != nil {
				return err
			}
			defer service.Close()
			auth := mailbox.LDAPAuth{Config: cfg.Auth}
			for _, source := range manifest.Accounts {
				account, err := auth.Resolve(cmd.Context(), source.Address)
				if err != nil {
					return fmt.Errorf("resolve %s: %w", source.Address, err)
				}
				if err := service.Engine().EnsureAccount(cmd.Context(), account); err != nil {
					return err
				}
				for _, folder := range source.Folders {
					if err := service.Engine().ImportOfflineFolder(cmd.Context(), account.ID, folder, root); err != nil {
						return fmt.Errorf("%s/%s: %w", source.Address, folder.Name, err)
					}
					fmt.Fprintf(cmd.OutOrStdout(), "%s/%s: %d messages verified\n", source.Address, folder.Name, len(folder.Messages))
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&snapshot, "snapshot", "", "Root containing manifest.json and Maildir files")
	cmd.Flags().BoolVar(&offline, "offline", false, "Confirm protocol services are stopped for the complete import and verification")
	mailboxCmd.AddCommand(cmd)
}
