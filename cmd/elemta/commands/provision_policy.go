package commands

// Classes of service, account policy and purging (internal/mailpolicy). They
// live in the mailbox service, so these commands go through its admin API
// rather than the directory.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/EvalAlan/elemta/internal/provision"
	"github.com/spf13/cobra"
)

type addCommand func(use string, aliases []string, short string, argc int, fn func(context.Context, *cobra.Command, *provision.Service, []string) (any, error)) *cobra.Command

// settingsFlags are the flags that set one layer of policy. Every flag
// takes "inherit" to unset the value, so the next layer down decides.
type settingsFlags struct {
	quota, maxMessage, maxAttachment                        string
	messagesPerHour, recipientsPerMessage, recipientsPerDay string
	maxForward, maxSenderRules, addressBook                 string
	protocols                                               string
	forwarding, filters, appPasswords, twoFactor            string
	trashDays, junkDays, retentionDays, legalHold           string
}

func (f *settingsFlags) register(c *cobra.Command) {
	fl := c.Flags()
	fl.StringVar(&f.quota, "quota", "", "Mailbox quota such as 5G; 0 is unlimited")
	fl.StringVar(&f.maxMessage, "max-message", "", "Largest message sent or received, such as 25M; 0 is unlimited")
	fl.StringVar(&f.maxAttachment, "max-attachment", "", "Largest single attachment, such as 10M; 0 is unlimited")
	fl.StringVar(&f.messagesPerHour, "messages-per-hour", "", "Messages the user may send per hour; 0 is unlimited")
	fl.StringVar(&f.recipientsPerMessage, "recipients-per-message", "", "Recipients per message sent; 0 is unlimited")
	fl.StringVar(&f.recipientsPerDay, "recipients-per-day", "", "Recipients per day across all mail sent; 0 is unlimited")
	fl.StringVar(&f.maxSenderRules, "max-sender-rules", "", "Allowed and blocked senders a user may keep, together (default 100); 0 is the most allowed, 5000")
	fl.StringVar(&f.addressBook, "address-book", "", "Offer the organisation's address book when writing: on, off or inherit (off by default)")
	fl.StringVar(&f.maxForward, "max-forward-addresses", "", "Addresses an account's mail may be forwarded to (default 3); 0 is the most allowed, 50")
	fl.StringVar(&f.protocols, "protocols", "", "Protocol switches, such as pop3=off,imap=on,dav=inherit (imap, pop3, webmail, dav, submission)")
	fl.StringVar(&f.forwarding, "external-forwarding", "", "Filters may forward mail outside the server: on, off or inherit")
	fl.StringVar(&f.filters, "filters", "", "Users may keep filters and vacation replies: on, off or inherit")
	fl.StringVar(&f.appPasswords, "require-app-passwords", "", "Mail apps must use app passwords: on, off or inherit")
	fl.StringVar(&f.twoFactor, "require-two-factor", "", "Webmail users must set up two-step verification: on, off or inherit")
	fl.StringVar(&f.trashDays, "trash-days", "", "Empty Trash of mail older than this many days there; 0 keeps it")
	fl.StringVar(&f.junkDays, "junk-days", "", "Empty Junk of mail older than this many days there; 0 keeps it")
	fl.StringVar(&f.retentionDays, "retention-days", "", "Delete mail in every folder older than this many days; 0 keeps it")
	fl.StringVar(&f.legalHold, "legal-hold", "", "Keep everything, even what the user deletes: on, off or inherit")
}

// apply changes s by the flags that were given and leaves the rest alone.
func (f *settingsFlags) apply(c *cobra.Command, s *mailpolicy.Settings) error {
	changed := c.Flags().Changed
	size := func(flag, v string, dst **int64) error {
		if !changed(flag) {
			return nil
		}
		if strings.EqualFold(v, "inherit") {
			*dst = nil
			return nil
		}
		n, err := provision.ParseQuota(v)
		if err != nil {
			return fmt.Errorf("--%s: %w", flag, err)
		}
		*dst = &n
		return nil
	}
	count := func(flag, v string, dst **int) error {
		if !changed(flag) {
			return nil
		}
		if strings.EqualFold(v, "inherit") {
			*dst = nil
			return nil
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return fmt.Errorf("--%s: give a whole number, 0 for unlimited, or inherit", flag)
		}
		*dst = &n
		return nil
	}
	toggle := func(flag, v string, dst **bool) error {
		if !changed(flag) {
			return nil
		}
		b, unset, err := parseSwitch(v)
		if err != nil {
			return fmt.Errorf("--%s: %w", flag, err)
		}
		if unset {
			*dst = nil
		} else {
			*dst = &b
		}
		return nil
	}
	for _, err := range []error{
		size("quota", f.quota, &s.QuotaBytes),
		size("max-message", f.maxMessage, &s.MaxMessageBytes),
		size("max-attachment", f.maxAttachment, &s.MaxAttachmentBytes),
		count("messages-per-hour", f.messagesPerHour, &s.MessagesPerHour),
		count("recipients-per-message", f.recipientsPerMessage, &s.RecipientsPerMessage),
		count("recipients-per-day", f.recipientsPerDay, &s.RecipientsPerDay),
		count("max-forward-addresses", f.maxForward, &s.MaxForwardAddresses),
		count("max-sender-rules", f.maxSenderRules, &s.MaxSenderRules),
		toggle("address-book", f.addressBook, &s.AddressBook),
		toggle("external-forwarding", f.forwarding, &s.ExternalForwarding),
		toggle("filters", f.filters, &s.Filters),
		toggle("require-app-passwords", f.appPasswords, &s.RequireAppPasswords),
		toggle("require-two-factor", f.twoFactor, &s.RequireTwoFactor),
		count("trash-days", f.trashDays, &s.TrashDays),
		count("junk-days", f.junkDays, &s.JunkDays),
		count("retention-days", f.retentionDays, &s.RetentionDays),
		toggle("legal-hold", f.legalHold, &s.LegalHold),
	} {
		if err != nil {
			return err
		}
	}
	if changed("protocols") {
		for _, item := range strings.Split(f.protocols, ",") {
			name, value, ok := strings.Cut(strings.TrimSpace(item), "=")
			if !ok {
				return fmt.Errorf("--protocols: write each as name=on, name=off or name=inherit")
			}
			b, unset, err := parseSwitch(value)
			if err != nil {
				return fmt.Errorf("--protocols %s: %w", name, err)
			}
			name = strings.ToLower(strings.TrimSpace(name))
			if unset {
				delete(s.Protocols, name)
				continue
			}
			if s.Protocols == nil {
				s.Protocols = map[string]bool{}
			}
			s.Protocols[name] = b
		}
	}
	return s.Validate()
}

func parseSwitch(v string) (value, unset bool, err error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "yes", "true", "allow":
		return true, false, nil
	case "off", "no", "false", "deny":
		return false, false, nil
	case "inherit", "":
		return false, true, nil
	}
	return false, false, fmt.Errorf("use on, off or inherit")
}

func addPolicyCommands(add addCommand) {
	admin := func(s *provision.Service) (*mailpolicy.Client, error) { return s.MailboxAdmin() }

	add("list-classes", []string{"gac"}, "List classes of service", 0, func(ctx context.Context, _ *cobra.Command, s *provision.Service, _ []string) (any, error) {
		c, err := admin(s)
		if err != nil {
			return nil, err
		}
		return c.Classes(ctx)
	})
	add("get-class <name>", []string{"gc"}, "Show a class of service", 1, func(ctx context.Context, _ *cobra.Command, s *provision.Service, args []string) (any, error) {
		c, err := admin(s)
		if err != nil {
			return nil, err
		}
		return c.Class(ctx, args[0])
	})
	var classFlags settingsFlags
	var description string
	setClass := add("set-class <name>", []string{"sc"}, "Create a class of service, or change some of its settings", 1, func(ctx context.Context, cmd *cobra.Command, s *provision.Service, args []string) (any, error) {
		c, err := admin(s)
		if err != nil {
			return nil, err
		}
		class, err := c.Class(ctx, args[0])
		if err != nil && !errors.Is(err, mailpolicy.ErrNotFound) {
			return nil, err
		}
		class.Name = args[0]
		if cmd.Flags().Changed("description") {
			class.Description = description
		}
		if err := classFlags.apply(cmd, &class.Settings); err != nil {
			return nil, err
		}
		return c.PutClass(ctx, class)
	})
	setClass.Flags().StringVar(&description, "description", "", "What the class is for")
	classFlags.register(setClass)
	add("delete-class <name>", []string{"dc"}, "Delete a class of service no account or domain uses", 1, func(ctx context.Context, _ *cobra.Command, s *provision.Service, args []string) (any, error) {
		c, err := admin(s)
		if err != nil {
			return nil, err
		}
		if err := c.DeleteClass(ctx, args[0]); err != nil {
			return nil, err
		}
		return map[string]string{"status": "class of service deleted"}, nil
	})
	add("list-domain-classes", []string{"gadc"}, "List domains and the class their accounts use by default", 0, func(ctx context.Context, _ *cobra.Command, s *provision.Service, _ []string) (any, error) {
		c, err := admin(s)
		if err != nil {
			return nil, err
		}
		return c.Domains(ctx)
	})
	add("set-domain-class <domain> <class>", []string{"sdc"}, `Set the class a domain's accounts use by default; "inherit" clears it`, 2, func(ctx context.Context, _ *cobra.Command, s *provision.Service, args []string) (any, error) {
		c, err := admin(s)
		if err != nil {
			return nil, err
		}
		class := args[1]
		if strings.EqualFold(class, "inherit") {
			class = ""
		}
		return c.SetDomain(ctx, mailpolicy.DomainPolicy{Domain: args[0], Class: class})
	})
	add("get-policy <email>", []string{"gp"}, "Show an account's class of service, its overrides, and what applies", 1, func(ctx context.Context, _ *cobra.Command, s *provision.Service, args []string) (any, error) {
		c, err := admin(s)
		if err != nil {
			return nil, err
		}
		address, err := provision.Address(args[0])
		if err != nil {
			return nil, err
		}
		return c.Account(ctx, address)
	})
	var accountFlags settingsFlags
	var accountClass string
	setPolicy := add("set-policy <email>", []string{"spol"}, "Set an account's class of service or override single settings", 1, func(ctx context.Context, cmd *cobra.Command, s *provision.Service, args []string) (any, error) {
		c, err := admin(s)
		if err != nil {
			return nil, err
		}
		address, err := provision.Address(args[0])
		if err != nil {
			return nil, err
		}
		view, err := c.Account(ctx, address)
		if err != nil {
			return nil, err
		}
		p := view.Policy
		p.Address = address
		if cmd.Flags().Changed("class") {
			p.Class = accountClass
			if strings.EqualFold(accountClass, "inherit") {
				p.Class = ""
			}
		}
		if err := accountFlags.apply(cmd, &p.Settings); err != nil {
			return nil, err
		}
		return c.PutAccount(ctx, p)
	})
	setPolicy.Flags().StringVar(&accountClass, "class", "", `The account's own class of service; "inherit" uses its domain's`)
	accountFlags.register(setPolicy)
	add("export-held <email>", []string{"eh"}, "Write the mail kept under an account's legal hold to stdout as mbox", 1, func(ctx context.Context, cmd *cobra.Command, s *provision.Service, args []string) (any, error) {
		c, err := admin(s)
		if err != nil {
			return nil, err
		}
		address, err := provision.Address(args[0])
		if err != nil {
			return nil, err
		}
		return nil, c.ExportHeld(ctx, address, cmd.OutOrStdout())
	})
	var purgeConfirm string
	purge := add("purge-account <email>", []string{"pa"}, "Permanently remove a deleted account's mail, folders, filters and settings", 1, func(ctx context.Context, _ *cobra.Command, s *provision.Service, args []string) (any, error) {
		if !strings.EqualFold(purgeConfirm, args[0]) {
			return nil, fmt.Errorf("repeat the email address with --confirm; purging permanently removes the mailbox's mail")
		}
		return s.Purge(ctx, args[0])
	})
	purge.Flags().StringVar(&purgeConfirm, "confirm", "", "Repeat the exact account email to confirm the purge")
}

func printPolicy(w *tabwriter.Writer, value any) bool {
	switch v := value.(type) {
	case []mailpolicy.Class:
		fmt.Fprintln(w, "CLASS\tACCOUNTS\tDOMAINS\tDESCRIPTION")
		for _, c := range v {
			fmt.Fprintf(w, "%s\t%d\t%d\t%s\n", c.Name, c.Accounts, c.Domains, c.Description)
		}
	case mailpolicy.Class:
		fmt.Fprintf(w, "Class:\t%s\nDescription:\t%s\nUsed by:\t%d accounts, %d domains\n", v.Name, v.Description, v.Accounts, v.Domains)
		printSettings(w, v.Settings)
	case []mailpolicy.DomainPolicy:
		fmt.Fprintln(w, "DOMAIN\tCLASS")
		for _, d := range v {
			fmt.Fprintf(w, "%s\t%s\n", d.Domain, d.Class)
		}
	case mailpolicy.DomainPolicy:
		if v.Class == "" {
			fmt.Fprintf(w, "%s now uses the default class\n", v.Domain)
		} else {
			fmt.Fprintf(w, "%s now uses class %s\n", v.Domain, v.Class)
		}
	case mailpolicy.AccountView:
		class := v.Policy.Class
		if class == "" {
			class = "(none of its own)"
		}
		fmt.Fprintf(w, "Account:\t%s\nOwn class:\t%s\n", v.Effective.Address, class)
		fmt.Fprintln(w, "Overrides:")
		printSettings(w, v.Policy.Settings)
		fmt.Fprintf(w, "\nIn effect (class %s):\n", v.Effective.Class)
		printEffective(w, v.Effective)
		if v.Held > 0 || v.Effective.LegalHold {
			fmt.Fprintf(w, "\nMessages on hold:\t%d (export-held writes them as mbox)\n", v.Held)
		}
	case mailpolicy.PurgeResult:
		fmt.Fprintf(w, "Purged %s: %d mailbox records, %d folders, %d messages. Message files are removed by the next cleanup after the backup grace period.\n", v.Address, v.Accounts, v.Folders, v.Messages)
	default:
		return false
	}
	return true
}

func printSettings(w *tabwriter.Writer, s mailpolicy.Settings) {
	printed := false
	line := func(name, value string) { printed = true; fmt.Fprintf(w, "  %s:\t%s\n", name, value) }
	size := func(name string, v *int64) {
		if v != nil {
			line(name, formatBytes(*v))
		}
	}
	count := func(name string, v *int) {
		if v != nil {
			line(name, formatCount(*v))
		}
	}
	toggle := func(name string, v *bool) {
		if v != nil {
			line(name, onOff(*v))
		}
	}
	days := func(name string, v *int) {
		if v != nil {
			line(name, formatDays(*v))
		}
	}
	size("quota", s.QuotaBytes)
	size("max message", s.MaxMessageBytes)
	size("max attachment", s.MaxAttachmentBytes)
	count("messages per hour", s.MessagesPerHour)
	count("recipients per message", s.RecipientsPerMessage)
	count("recipients per day", s.RecipientsPerDay)
	count("forwarding addresses", s.MaxForwardAddresses)
	count("allowed and blocked senders", s.MaxSenderRules)
	toggle("address book", s.AddressBook)
	names := make([]string, 0, len(s.Protocols))
	for p := range s.Protocols {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		line("protocol "+p, onOff(s.Protocols[p]))
	}
	toggle("external forwarding", s.ExternalForwarding)
	toggle("filters", s.Filters)
	toggle("require app passwords", s.RequireAppPasswords)
	toggle("require two-step verification", s.RequireTwoFactor)
	days("empty Trash after", s.TrashDays)
	days("empty Junk after", s.JunkDays)
	days("delete mail older than", s.RetentionDays)
	toggle("legal hold", s.LegalHold)
	if !printed {
		fmt.Fprintln(w, "  (nothing set; everything is inherited)")
	}
}

func printEffective(w *tabwriter.Writer, e mailpolicy.Effective) {
	src := func(field string) string {
		if s := e.Source[field]; s != "" {
			return s
		}
		return "built-in"
	}
	fmt.Fprintf(w, "  quota:\t%s\t(%s)\n", formatBytes(e.QuotaBytes), src("quota_bytes"))
	fmt.Fprintf(w, "  max message:\t%s\t(%s)\n", formatBytes(e.MaxMessageBytes), src("max_message_bytes"))
	fmt.Fprintf(w, "  max attachment:\t%s\t(%s)\n", formatBytes(e.MaxAttachmentBytes), src("max_attachment_bytes"))
	fmt.Fprintf(w, "  messages per hour:\t%s\t(%s)\n", formatCount(e.MessagesPerHour), src("messages_per_hour"))
	fmt.Fprintf(w, "  recipients per message:\t%s\t(%s)\n", formatCount(e.RecipientsPerMessage), src("recipients_per_message"))
	fmt.Fprintf(w, "  recipients per day:\t%s\t(%s)\n", formatCount(e.RecipientsPerDay), src("recipients_per_day"))
	fmt.Fprintf(w, "  forwarding addresses:\t%d\t(%s)\n", e.ForwardLimit(), src("max_forward_addresses"))
	fmt.Fprintf(w, "  allowed and blocked senders:\t%d\t(%s)\n", e.SenderRuleLimit(), src("max_sender_rules"))
	fmt.Fprintf(w, "  address book:\t%s\t(%s)\n", onOff(e.AddressBook), src("address_book"))
	for _, p := range mailpolicy.Protocols {
		fmt.Fprintf(w, "  protocol %s:\t%s\t(%s)\n", p, onOff(e.Allows(p)), src("protocols."+p))
	}
	fmt.Fprintf(w, "  external forwarding:\t%s\t(%s)\n", onOff(e.ExternalForwarding), src("external_forwarding"))
	fmt.Fprintf(w, "  filters:\t%s\t(%s)\n", onOff(e.Filters), src("filters"))
	fmt.Fprintf(w, "  require app passwords:\t%s\t(%s)\n", onOff(e.RequireAppPasswords), src("require_app_passwords"))
	fmt.Fprintf(w, "  require two-step verification:\t%s\t(%s)\n", onOff(e.RequireTwoFactor), src("require_two_factor"))
	fmt.Fprintf(w, "  empty Trash after:\t%s\t(%s)\n", formatDays(e.TrashDays), src("trash_days"))
	fmt.Fprintf(w, "  empty Junk after:\t%s\t(%s)\n", formatDays(e.JunkDays), src("junk_days"))
	fmt.Fprintf(w, "  delete mail older than:\t%s\t(%s)\n", formatDays(e.RetentionDays), src("retention_days"))
	fmt.Fprintf(w, "  legal hold:\t%s\t(%s)\n", onOff(e.LegalHold), src("legal_hold"))
}

func formatDays(n int) string {
	if n == 0 {
		return "never"
	}
	return strconv.Itoa(n) + " days"
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func formatCount(n int) string {
	if n == 0 {
		return "unlimited"
	}
	return strconv.Itoa(n)
}

func formatBytes(n int64) string {
	switch {
	case n == 0:
		return "unlimited"
	case n%(1<<30) == 0:
		return strconv.FormatInt(n>>30, 10) + "G"
	case n%(1<<20) == 0:
		return strconv.FormatInt(n>>20, 10) + "M"
	case n%(1<<10) == 0:
		return strconv.FormatInt(n>>10, 10) + "K"
	}
	return strconv.FormatInt(n, 10) + " bytes"
}
