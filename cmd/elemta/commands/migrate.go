package commands

// elemta migrate: moving users onto Elemta from another mail system
// (internal/migrate). Mail is copied over IMAP; calendars, tasks and
// contacts come from .ics and .vcf exports; accounts, aliases and lists
// come from a CSV. Everything can be run again: what was already copied is
// recognised and skipped, so an interrupted migration is resumed by
// repeating the command, and a final pass just before switching MX picks
// up the mail that arrived since.

import (
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"

	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/EvalAlan/elemta/internal/migrate"
	"github.com/EvalAlan/elemta/internal/provision"
	"github.com/spf13/cobra"
)

func init() { rootCmd.AddCommand(newMigrateCommand(defaultProvisionOpen)) }

// readCSV reads a CSV with a header row into maps keyed by lower-case
// column name, ignoring blank lines and lines starting with #.
func readCSV(path string) ([]map[string]string, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator's own input file
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.Comment = '#'
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(rows) < 1 {
		return nil, fmt.Errorf("%s: no header row", path)
	}
	header := rows[0]
	for i := range header {
		header[i] = strings.ToLower(strings.TrimSpace(header[i]))
	}
	var out []map[string]string
	for _, row := range rows[1:] {
		m := map[string]string{}
		empty := true
		for i, v := range row {
			if i < len(header) {
				m[header[i]] = strings.TrimSpace(v)
				empty = empty && strings.TrimSpace(v) == ""
			}
		}
		if !empty {
			out = append(out, m)
		}
	}
	return out, nil
}

func splitValues(v string) []string {
	var out []string
	for _, item := range strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == '|' || r == ' ' }) {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func newMigrateCommand(open func() (*provision.Service, error)) *cobra.Command {
	var asJSON bool
	root := &cobra.Command{Use: "migrate", Short: "Move mail, calendars, contacts and accounts onto Elemta",
		Long: "Copy users from another mail system. Every command can be run again: what was already copied is skipped, so an interrupted run is resumed by repeating it, and a last pass before changing MX picks up new mail. Passwords are prompted for or read from stdin or a CSV, never command arguments."}
	root.PersistentFlags().BoolVar(&asJSON, "json", false, "Output JSON for scripts")

	admin := func() (*mailpolicy.Client, error) {
		s, err := open()
		if err != nil {
			return nil, err
		}
		return s.MailboxAdmin()
	}
	output := func(cmd *cobra.Command, v any, text func(w *tabwriter.Writer)) error {
		if asJSON {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(v)
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		text(w)
		return w.Flush()
	}

	// ---- mail -----------------------------------------------------------------
	var src migrate.Source
	var sourceUser, dest, users, stateDir, exclude string
	var parallel int
	mail := &cobra.Command{
		// A failed migration explains itself; the usage text would bury it.
		SilenceUsage: true,
		Use:          "mail",
		Short:        "Copy mail over IMAP, for one user (--source-user, --dest) or many (--users file.csv)",
		Long: `Copy every folder of a user's mailbox from another IMAP server, keeping folders, read and flagged state, and dates.
Sent, Drafts, Trash, Junk and Archive folders are recognised and land in the webmail's own; messages marked deleted are left behind.

One user:  migrate mail --source old.example.com:993 --source-user dana --dest dana@example.com   (password prompted or on stdin)
Many:      migrate mail --source old.example.com:993 --users users.csv
           users.csv columns: dest,source_user[,source_password]
Admin:     add --source-admin admin@old.example.com to sign in on each user's behalf with the administrator's password
           (prompted or on stdin), when the source supports it; then no user passwords are needed.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := admin()
			if err != nil {
				return err
			}
			type job struct {
				src  migrate.Source
				dest string
			}
			var jobs []job
			needsPassword := src.Admin != ""
			if users != "" {
				rows, err := readCSV(users)
				if err != nil {
					return err
				}
				for i, r := range rows {
					if r["dest"] == "" || r["source_user"] == "" {
						return fmt.Errorf("%s row %d: dest and source_user are required", users, i+2)
					}
					j := job{src: src, dest: r["dest"]}
					j.src.User, j.src.Password = r["source_user"], r["source_password"]
					if j.src.Password == "" && src.Admin == "" {
						return fmt.Errorf("%s row %d: no source_password, and no --source-admin", users, i+2)
					}
					jobs = append(jobs, j)
				}
			} else {
				if sourceUser == "" || dest == "" {
					return fmt.Errorf("give --source-user and --dest, or --users file.csv")
				}
				j := job{src: src, dest: dest}
				j.src.User = sourceUser
				jobs = append(jobs, j)
				needsPassword = true
			}
			if needsPassword {
				pw, err := readPassword(cmd, false)
				if err != nil {
					return err
				}
				for i := range jobs {
					if jobs[i].src.Password == "" || src.Admin != "" {
						jobs[i].src.Password = pw
					}
				}
			}
			opts := migrate.Options{StateDir: stateDir, Exclude: splitValues(exclude), Log: slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil))}
			reports := make([]migrate.Report, len(jobs))
			var wg sync.WaitGroup
			slots := make(chan struct{}, max(1, parallel))
			for i, j := range jobs {
				wg.Add(1)
				go func() {
					defer wg.Done()
					slots <- struct{}{}
					defer func() { <-slots }()
					rep, err := migrate.Mail(cmd.Context(), j.src, j.dest, client, opts)
					if err != nil {
						rep.Error = err.Error()
					}
					reports[i] = rep
				}()
			}
			wg.Wait()
			failed := 0
			for _, r := range reports {
				if r.Error != "" {
					failed++
				}
			}
			err = output(cmd, reports, func(w *tabwriter.Writer) {
				fmt.Fprintln(w, "SOURCE USER\tDEST\tCOPIED\tALREADY\tTOO LARGE\tFAILED\tRESULT")
				for _, r := range reports {
					t := r.Totals()
					result := "done"
					if r.Error != "" {
						result = r.Error
					}
					fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%d\t%s\n", r.User, r.Dest, t.Copied, t.Skipped, t.TooLarge, t.Failed, result)
				}
			})
			if err == nil && failed > 0 {
				err = fmt.Errorf("%d of %d users didn't finish; fix the cause and run the same command again", failed, len(reports))
			}
			return err
		},
	}
	mail.Flags().StringVar(&src.Addr, "source", "", "Source IMAP server, host:port")
	mail.Flags().StringVar(&src.TLS, "source-tls", "imaps", "imaps, starttls or none")
	mail.Flags().BoolVar(&src.InsecureSkipVerify, "source-insecure", false, "Accept the source's certificate without verifying it")
	mail.Flags().StringVar(&src.Admin, "source-admin", "", "Administrator to sign in as on each user's behalf")
	mail.Flags().StringVar(&sourceUser, "source-user", "", "The user's login at the source")
	mail.Flags().StringVar(&dest, "dest", "", "The user's primary address here")
	mail.Flags().StringVar(&users, "users", "", "CSV of users: dest,source_user[,source_password]")
	mail.Flags().StringVar(&stateDir, "state-dir", "migrate-state", "Where progress is kept, so reruns skip what was copied")
	mail.Flags().StringVar(&exclude, "exclude", "", "Source folders not to copy, separated by ;")
	mail.Flags().IntVar(&parallel, "parallel", 4, "Users copied at the same time")
	_ = mail.MarkFlagRequired("source")
	root.AddCommand(mail)

	// ---- calendars, tasks and contacts ---------------------------------------
	var fileDest string
	files := &cobra.Command{
		// A failed migration explains itself; the usage text would bury it.
		SilenceUsage: true,
		Use:          "import-files <file.ics|file.vcf>...",
		Short:        "Import calendar (.ics) and contact (.vcf) exports into a user's calendar, tasks and contacts",
		Args:         cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := admin()
			if err != nil {
				return err
			}
			if fileDest == "" {
				return fmt.Errorf("--dest is required")
			}
			var objs []migrate.Object
			for _, path := range args {
				f, err := os.Open(path) // #nosec G304 -- the operator's own export files
				if err != nil {
					return err
				}
				var got []migrate.Object
				switch strings.ToLower(filepath.Ext(path)) {
				case ".ics", ".ical", ".ifb":
					got, err = migrate.SplitCalendar(f)
				case ".vcf", ".vcard":
					got, err = migrate.SplitContacts(f)
				default:
					err = fmt.Errorf("%s: use .ics files for calendars and tasks and .vcf files for contacts", path)
				}
				_ = f.Close()
				if err != nil {
					return fmt.Errorf("%s: %w", path, err)
				}
				objs = append(objs, got...)
			}
			rep, err := migrate.ImportObjects(cmd.Context(), fileDest, objs, client)
			if oerr := output(cmd, rep, func(w *tabwriter.Writer) {
				fmt.Fprintf(w, "%s: %d imported, %d already there, %d failed\n", fileDest, rep.Imported, rep.Skipped, rep.Failed)
			}); err == nil {
				err = oerr
			}
			return err
		},
	}
	files.Flags().StringVar(&fileDest, "dest", "", "The user's primary address here")
	root.AddCommand(files)

	// ---- accounts, aliases, classes and lists -------------------------------
	var csvPath string
	accounts := &cobra.Command{
		// A failed migration explains itself; the usage text would bury it.
		SilenceUsage: true,
		Use:          "accounts",
		Short:        "Create accounts, aliases, classes of service and distribution lists from a CSV",
		Long: `Each row is an account or a list, by its type column:

  type,address,name,quota,password,aliases,class,members,owner,posting
  account,dana@example.com,Dana Jones,5G,,dana.jones@example.com;dj@example.com,staff,,,
  list,team@example.com,Team,,,,,dana@example.com;partner@other.example,dana@example.com,members

Accounts that already exist are left as they are, apart from adding missing aliases and setting the class, so the file
can be run again. Lists are created or replaced. An empty password sets a random one that nobody knows: reset it, or let
the user recover it, before they sign in. Several aliases or members are separated by ; or |.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := open()
			if err != nil {
				return err
			}
			rows, err := readCSV(csvPath)
			if err != nil {
				return err
			}
			rep := migrateAccounts(cmd.Context(), s, rows)
			err = output(cmd, rep, func(w *tabwriter.Writer) {
				fmt.Fprintf(w, "Accounts created:\t%d\nAccounts already there:\t%d\nAliases added:\t%d\nClasses set:\t%d\nLists saved:\t%d\n", rep.Created, rep.Existing, rep.Aliases, rep.Classes, rep.Lists)
				if len(rep.RandomPasswords) > 0 {
					fmt.Fprintf(w, "Random passwords (reset before use):\t%s\n", strings.Join(rep.RandomPasswords, ", "))
				}
				for _, e := range rep.Errors {
					fmt.Fprintf(w, "ERROR\t%s\n", e)
				}
			})
			if err == nil && len(rep.Errors) > 0 {
				err = fmt.Errorf("%d rows had problems; fix them and run the same file again", len(rep.Errors))
			}
			return err
		},
	}
	accounts.Flags().StringVar(&csvPath, "csv", "", "The CSV file")
	_ = accounts.MarkFlagRequired("csv")
	root.AddCommand(accounts)
	return root
}

type accountsReport struct {
	Created, Existing, Aliases, Classes, Lists int
	RandomPasswords                            []string `json:"random_passwords,omitempty"`
	Errors                                     []string `json:"errors,omitempty"`
}

func randomPassword() (string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 32)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b[i] = alphabet[n.Int64()]
	}
	return string(b), nil
}

// migrateAccounts applies the CSV: accounts (with aliases and class) first,
// then lists, which may name those accounts.
func migrateAccounts(ctx context.Context, s *provision.Service, rows []map[string]string) accountsReport {
	var rep accountsReport
	fail := func(i int, format string, args ...any) {
		rep.Errors = append(rep.Errors, fmt.Sprintf("row %d: ", i+2)+fmt.Sprintf(format, args...))
	}
	audit := func(action, target, detail string) {
		_ = s.Audit(ctx, mailpolicy.AuditEntry{Actor: cliActor(), Source: "migrate", Action: action, Target: target, Detail: detail})
	}
	for i, r := range rows {
		if !strings.EqualFold(r["type"], "account") && r["type"] != "" {
			continue
		}
		address, err := provision.Address(r["address"])
		if err != nil {
			fail(i, "%v", err)
			continue
		}
		existing, err := s.Get(ctx, address)
		switch {
		case err == nil:
			rep.Existing++
		case errors.Is(err, provision.ErrNotFound):
			quota, err := provision.ParseQuota(r["quota"])
			if err != nil {
				fail(i, "%v", err)
				continue
			}
			name := r["name"]
			if name == "" {
				name = address
			}
			password := r["password"]
			if password == "" {
				if password, err = randomPassword(); err != nil {
					fail(i, "%v", err)
					continue
				}
				rep.RandomPasswords = append(rep.RandomPasswords, address)
			}
			if existing, err = s.Create(ctx, provision.Create{Address: address, Name: name, QuotaBytes: quota, Password: password}); err != nil {
				fail(i, "create %s: %v", address, err)
				continue
			}
			rep.Created++
			audit("account-create", address, fmt.Sprintf("quota %d", quota))
		default:
			fail(i, "look up %s: %v", address, err)
			continue
		}
		for _, alias := range splitValues(r["aliases"]) {
			alias = strings.ToLower(alias)
			has := false
			for _, a := range existing.Aliases {
				has = has || strings.EqualFold(a, alias)
			}
			if has {
				continue
			}
			if _, err := s.Alias(ctx, address, alias, true); err != nil {
				fail(i, "alias %s: %v", alias, err)
				continue
			}
			rep.Aliases++
			audit("alias-add", address, alias)
		}
		if class := r["class"]; class != "" {
			client, err := s.MailboxAdmin()
			if err == nil {
				var view mailpolicy.AccountView
				if view, err = client.Account(ctx, address); err == nil {
					p := view.Policy
					p.Address, p.Class = address, class
					_, err = client.PutAccount(ctx, p)
				}
			}
			if err != nil {
				fail(i, "class %s for %s: %v", class, address, err)
				continue
			}
			rep.Classes++
			audit("account-policy", address, "class "+class)
		}
	}
	for i, r := range rows {
		if !strings.EqualFold(r["type"], "list") {
			continue
		}
		l := mailpolicy.List{Address: r["address"], Name: r["name"], Owner: r["owner"], Posting: r["posting"], Members: splitValues(r["members"])}
		if _, err := s.PutList(ctx, l); err != nil {
			fail(i, "list %s: %v", l.Address, err)
			continue
		}
		rep.Lists++
		audit("list-set", l.Address, fmt.Sprintf("%d members", len(l.Members)))
	}
	return rep
}
