package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/EvalAlan/elemta/internal/config"
	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/EvalAlan/elemta/internal/provision"
	"github.com/EvalAlan/elemta/internal/webmail"
	"github.com/spf13/cobra"
)

func openProvision(c *config.Config, path string) (*provision.Service, error) {
	if c == nil || c.Webmail == nil || path == "" {
		return nil, provision.ErrUnavailable
	}
	wc := c.Webmail.WithDefaults()
	if wc.SessionStore != "valkey" {
		return nil, fmt.Errorf("mail administration requires shared Valkey sessions")
	}
	// Administration binds as its own account when one is configured, so the
	// reset account needs no right to create or delete mailboxes.
	bindDN, password := wc.LDAPProvisionDN, wc.LDAPProvisionPassword
	if v := os.Getenv("ELEMTA_LDAP_PROVISION_PASSWORD"); v != "" {
		password = v
	}
	if bindDN == "" {
		bindDN, password = wc.LDAPResetDN, wc.LDAPResetPassword
		if v := os.Getenv("ELEMTA_WEBMAIL_LDAP_RESET_PASSWORD"); v != "" {
			password = v
		}
	}
	directory, err := provision.NewLDAP(provision.LDAPConfig{URL: wc.LDAPURL, Base: wc.LDAPBase, BindDN: bindDN, Password: password, SkipVerify: wc.InsecureSkipVerify})
	if err != nil {
		return nil, err
	}
	mail, err := webmail.NewServer(wc, nil, nil, slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err != nil {
		return nil, err
	}
	service := &provision.Service{Directory: directory, Routing: provision.FileDomains{Path: path}, Revoke: mail.AdminRevokeAccount, Remove: mail.AdminRemoveAccount, Reset: mail.AdminResetPassword, MinPasswordLength: wc.MinPasswordLength}
	// The mailbox admin API is optional: account and domain commands work
	// without it, and the class-of-service commands say how to set it up.
	securityURL := os.Getenv("ELEMTA_AUTH_MAILBOX_SECURITY_URL")
	if securityURL == "" && c.Auth != nil {
		securityURL = c.Auth.MailboxSecurityURL
	}
	if client, err := mailpolicy.FromEnv(securityURL); err == nil {
		service.Mailbox = client
	} else if !errors.Is(err, mailpolicy.ErrUnavailable) {
		return nil, err
	}
	return service, nil
}
func defaultProvisionOpen() (*provision.Service, error) {
	path, err := config.FindConfigFile(configPath)
	if err != nil {
		return nil, err
	}
	return openProvision(GetConfig(), path)
}
func init() { rootCmd.AddCommand(newProvisionCommand(defaultProvisionOpen)) }

func newProvisionCommand(open func() (*provision.Service, error)) *cobra.Command {
	var asJSON bool
	root := &cobra.Command{Use: "provision", Short: "Manage mailbox accounts, domains and delivery aliases", Long: "Provision the same mailbox directory used by webmail and the mail administration console. Passwords are prompted for or read from stdin; they are never command arguments."}
	root.PersistentFlags().BoolVar(&asJSON, "json", false, "Output JSON for scripts")
	run := func(fn func(context.Context, *cobra.Command, *provision.Service, []string) (any, error)) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, args []string) error {
			service, err := open()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			value, err := fn(ctx, cmd, service, args)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(value)
			}
			return printProvision(cmd, value)
		}
	}
	add := func(use string, aliases []string, short string, argc int, fn func(context.Context, *cobra.Command, *provision.Service, []string) (any, error)) *cobra.Command {
		c := &cobra.Command{Use: use, Aliases: aliases, Short: short, Args: cobra.ExactArgs(argc), RunE: run(fn)}
		root.AddCommand(c)
		return c
	}
	add("list-accounts", []string{"gaa"}, "List mailbox accounts", 0, func(ctx context.Context, _ *cobra.Command, s *provision.Service, _ []string) (any, error) {
		return s.List(ctx)
	})
	add("get-account <email>", []string{"ga"}, "Show an account and its aliases", 1, func(ctx context.Context, _ *cobra.Command, s *provision.Service, args []string) (any, error) {
		return s.Get(ctx, args[0])
	})
	var name, quota string
	create := add("create-account <email>", []string{"ca"}, "Create a mailbox account", 1, func(ctx context.Context, cmd *cobra.Command, s *provision.Service, args []string) (any, error) {
		bytes, err := provision.ParseQuota(quota)
		if err != nil {
			return nil, err
		}
		password, err := readPassword(cmd, true)
		if err != nil {
			return nil, err
		}
		return s.Create(ctx, provision.Create{Address: args[0], Name: name, QuotaBytes: bytes, Password: password})
	})
	create.Flags().StringVar(&name, "name", "", "Display name (required)")
	_ = create.MarkFlagRequired("name")
	create.Flags().StringVar(&quota, "quota", "0", "Quota such as 5G, or 0 for unlimited")
	var newName, status, newQuota string
	modify := add("modify-account <email>", []string{"ma"}, "Update name, status or quota", 1, func(ctx context.Context, cmd *cobra.Command, s *provision.Service, args []string) (any, error) {
		p := provision.Patch{}
		if cmd.Flags().Changed("name") {
			p.Name = &newName
		}
		if cmd.Flags().Changed("status") {
			p.Status = &status
		}
		if cmd.Flags().Changed("quota") {
			n, err := provision.ParseQuota(newQuota)
			if err != nil {
				return nil, err
			}
			p.QuotaBytes = &n
		}
		return s.Update(ctx, args[0], p)
	})
	modify.Flags().StringVar(&newName, "name", "", "New display name")
	modify.Flags().StringVar(&status, "status", "", "active or disabled")
	modify.Flags().StringVar(&newQuota, "quota", "", "New quota; 0 is unlimited")
	add("set-password <email>", []string{"sp"}, "Reset a mailbox password and revoke webmail sessions", 1, func(ctx context.Context, cmd *cobra.Command, s *provision.Service, args []string) (any, error) {
		password, err := readPassword(cmd, true)
		if err != nil {
			return nil, err
		}
		if err = s.Password(ctx, args[0], password); err != nil {
			return nil, err
		}
		return map[string]string{"status": "password reset; webmail sessions ended"}, nil
	})
	var confirm string
	var purgeToo bool
	del := add("delete-account <email>", []string{"da"}, "Remove an account, retaining its mailbox unless --purge is given", 1, func(ctx context.Context, _ *cobra.Command, s *provision.Service, args []string) (any, error) {
		if !strings.EqualFold(confirm, args[0]) {
			return nil, fmt.Errorf("repeat the email address with --confirm to delete this account")
		}
		if purgeToo {
			// Checked first, so a missing admin token doesn't leave the
			// account deleted and its mail behind.
			if _, err := s.MailboxAdmin(); err != nil {
				return nil, err
			}
		}
		if err := s.Delete(ctx, args[0]); err != nil {
			return nil, err
		}
		if !purgeToo {
			return map[string]string{"status": "account removed; mailbox files retained (purge-account removes them)"}, nil
		}
		return s.Purge(ctx, args[0])
	})
	del.Flags().StringVar(&confirm, "confirm", "", "Repeat the exact account email to confirm removal")
	del.Flags().BoolVar(&purgeToo, "purge", false, "Also permanently remove the account's mail, folders, filters and settings")
	for _, operation := range []struct {
		use, alias, short string
		add               bool
	}{{"add-alias <email> <alias>", "aaa", "Add a delivery alias", true}, {"remove-alias <email> <alias>", "raa", "Remove a delivery alias", false}} {
		add(operation.use, []string{operation.alias}, operation.short, 2, func(ctx context.Context, _ *cobra.Command, s *provision.Service, args []string) (any, error) {
			return s.Alias(ctx, args[0], args[1], operation.add)
		})
	}
	add("list-domains", []string{"gad"}, "List configured domains and mailbox counts", 0, func(ctx context.Context, _ *cobra.Command, s *provision.Service, _ []string) (any, error) {
		return s.Domains(ctx)
	})
	for _, operation := range []struct {
		use, alias, short string
		add               bool
	}{{"create-domain <domain>", "cd", "Configure a local domain (SMTP restart required)", true}, {"delete-domain <domain>", "dd", "Remove an empty local domain (SMTP restart required)", false}} {
		add(operation.use, []string{operation.alias}, operation.short, 1, func(ctx context.Context, _ *cobra.Command, s *provision.Service, args []string) (any, error) {
			if err := s.Domain(ctx, args[0], operation.add); err != nil {
				return nil, err
			}
			return map[string]string{"status": "domain configuration saved; SMTP restart required"}, nil
		})
	}
	addPolicyCommands(add)
	return root
}
func printProvision(cmd *cobra.Command, value any) error {
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	if printPolicy(w, value) {
		return w.Flush()
	}
	switch v := value.(type) {
	case []provision.Account:
		fmt.Fprintln(w, "ADDRESS\tNAME\tSTATUS\tQUOTA BYTES\tALIASES")
		for _, a := range v {
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\n", a.Address, a.Name, a.Status, a.QuotaBytes, len(a.Aliases))
		}
	case provision.Account:
		fmt.Fprintf(w, "Address:\t%s\nName:\t%s\nStatus:\t%s\nQuota bytes:\t%d (0 = unlimited)\n", v.Address, v.Name, v.Status, v.QuotaBytes)
		for _, a := range v.Aliases {
			fmt.Fprintf(w, "Alias:\t%s\n", a)
		}
	case []provision.Domain:
		fmt.Fprintln(w, "DOMAIN\tCONFIGURED\tACCOUNTS\tALIASES")
		for _, d := range v {
			fmt.Fprintf(w, "%s\t%t\t%d\t%d\n", d.Name, d.Configured, d.Accounts, d.Aliases)
		}
	case map[string]string:
		fmt.Fprintln(w, v["status"])
	default:
		return fmt.Errorf("unsupported provisioning output")
	}
	return w.Flush()
}
