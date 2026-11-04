package commands

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/EvalAlan/elemta/internal/mailbox"
	"github.com/spf13/cobra"
)

// Restores one account from a backup, and writes a store's bodies out for one.
// scripts/mailbox-restore-account.sh and scripts/mailbox-backup.sh drive these;
// they need a backup's metadata in a database and its bodies in a directory.
func init() {
	var database, bodies, address, label, actor string
	var folders []string
	var all, dryRun, data, objectsElsewhere bool
	restore := &cobra.Command{
		Use: "restore-account", Short: "Put one account's lost mail back from a backup, in a separate folder",
		RunE: func(cmd *cobra.Command, _ []string) error {
			service, err := openMailboxService(cmd)
			if err != nil {
				return err
			}
			defer service.Close()
			source, err := service.OpenRestoreSource(cmd.Context(), database)
			if err != nil {
				return err
			}
			defer source.Close()
			store, err := mailbox.NewFileBodies(bodies)
			if err != nil {
				return err
			}
			defer store.Close()
			out := cmd.OutOrStdout()
			r, err := service.Engine().RestoreAccount(cmd.Context(), mailbox.RestoreRequest{
				Source: source, Bodies: store, Address: address, Label: label,
				Folders: folders, All: all, DryRun: dryRun, Actor: actor,
				Data: data, ObjectsElsewhere: objectsElsewhere,
			}, func(n int) { fmt.Fprintf(out, "%d messages checked\n", n) })
			if err != nil {
				return err
			}
			verb := "restored"
			if dryRun {
				verb = "would restore"
			}
			fmt.Fprintf(out, "%s %d messages under %q\n", verb, r.Restored, r.Target)
			fmt.Fprintf(out, "%d still in the account, %d restored by an earlier run\n", r.Present, r.Repeated)
			if data || r.Objects+r.ObjectsPresent > 0 {
				fmt.Fprintf(out, "%s %d calendar, contact, task and settings items, %d filters (switched off) and %d sender rules; %d items still in the account\n",
					verb, r.Objects, r.Filters, r.SenderRules, r.ObjectsPresent)
			}
			fmt.Fprintf(out, "%d bytes in all\n", r.Bytes)
			for _, f := range r.LeftOut {
				fmt.Fprintf(out, "left out %s (name it with --folder, or --data for all webmail data)\n", f)
			}
			for _, u := range r.Unreadable {
				fmt.Fprintf(out, "unreadable %s\n", u)
			}
			if r.QuotaFull || dryRun && r.Free >= 0 && r.Bytes > r.Free {
				fmt.Fprintf(out, "over quota: %d bytes free; raise the quota and run this again, it carries on\n", r.Free)
			}
			if !r.Complete() {
				return fmt.Errorf("the restore is incomplete")
			}
			return nil
		},
	}
	f := restore.Flags()
	f.StringVar(&database, "source-database", "", "database on the mailbox's server holding the backup's metadata")
	f.StringVar(&bodies, "bodies", "", "directory holding the backup's bodies")
	f.StringVar(&address, "address", "", "the account to restore")
	f.StringVar(&label, "label", "", "name for the Restored folder, normally the backup's date")
	f.StringArrayVar(&folders, "folder", nil, "restore only this source folder (repeatable)")
	f.BoolVar(&all, "all", false, "also restore messages the account still has")
	f.BoolVar(&dryRun, "dry-run", false, "read everything and report, writing nothing")
	f.BoolVar(&data, "data", false, "also restore missing calendar items, contacts, tasks, settings, filters and sender rules")
	f.BoolVar(&objectsElsewhere, "objects-elsewhere", false, "webmail keeps its objects in their own database; leave the hidden folders alone")
	f.StringVar(&actor, "actor", "", "who asked, for the audit log")
	for _, name := range []string{"source-database", "bodies", "address", "label"} {
		_ = restore.MarkFlagRequired(name)
	}
	mailboxCmd.AddCommand(restore)

	mailboxCmd.AddCommand(&cobra.Command{
		Use: "export-bodies", Short: "Write every stored message body to standard output as a gzipped tar",
		RunE: func(cmd *cobra.Command, _ []string) error {
			service, err := openMailboxService(cmd)
			if err != nil {
				return err
			}
			defer service.Close()
			r, err := service.Engine().ExportBodies(cmd.Context(), cmd.OutOrStdout(), func(n int) { fmt.Fprintf(os.Stderr, "%d bodies written\n", n) })
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "exported %d bodies, %d bytes\n", r.Bodies, r.Bytes)
			return nil
		},
	})
}

// openMailboxService logs to standard error because export-bodies' standard
// output is the archive.
func openMailboxService(cmd *cobra.Command) (*mailbox.Service, error) {
	path := configPath
	if path == "" {
		path = "config/mailbox.toml"
	}
	cfg, err := mailbox.LoadConfig(path)
	if err != nil {
		return nil, err
	}
	return mailbox.Open(cmd.Context(), cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)))
}
