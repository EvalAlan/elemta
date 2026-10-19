package commands

// Distribution lists, domain aliases and catch-alls (internal/provision/
// addressing.go). Like classes of service they live in the mailbox service
// and need its admin API.

import (
	"context"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/EvalAlan/elemta/internal/provision"
	"github.com/spf13/cobra"
)

func splitList(v string) []string {
	var out []string
	for _, item := range strings.Split(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func addAddressingCommands(add addCommand) {
	add("list-lists", []string{"gadl"}, "List distribution lists", 0, func(ctx context.Context, _ *cobra.Command, s *provision.Service, _ []string) (any, error) {
		return s.Lists(ctx)
	})
	add("get-list <address>", []string{"gdl"}, "Show a distribution list and its members", 1, func(ctx context.Context, _ *cobra.Command, s *provision.Service, args []string) (any, error) {
		return s.GetList(ctx, args[0])
	})
	var name, description, owner, posting, members string
	listFlags := func(c *cobra.Command) {
		c.Flags().StringVar(&name, "name", "", "Display name, shown in List-Id")
		c.Flags().StringVar(&description, "description", "", "What the list is for")
		c.Flags().StringVar(&owner, "owner", "", "Address that receives bounces; empty drops them")
		c.Flags().StringVar(&posting, "posting", "", "Who may post: anyone, members, domain or owner")
		c.Flags().StringVar(&members, "members", "", "Comma-separated member addresses, local or external")
	}
	create := add("create-list <address>", []string{"cdl"}, "Create a distribution list", 1, func(ctx context.Context, cmd *cobra.Command, s *provision.Service, args []string) (any, error) {
		if _, err := s.GetList(ctx, args[0]); err == nil {
			return nil, fmt.Errorf("%w: %s is already a list; use set-list", provision.ErrExists, args[0])
		}
		return s.PutList(ctx, mailpolicy.List{Address: args[0], Name: name, Description: description, Owner: owner, Posting: posting, Members: splitList(members)})
	})
	listFlags(create)
	set := add("set-list <address>", []string{"sdl"}, "Change a list's settings; --members replaces all members", 1, func(ctx context.Context, cmd *cobra.Command, s *provision.Service, args []string) (any, error) {
		l, err := s.GetList(ctx, args[0])
		if err != nil {
			return nil, err
		}
		changed := cmd.Flags().Changed
		if changed("name") {
			l.Name = name
		}
		if changed("description") {
			l.Description = description
		}
		if changed("owner") {
			l.Owner = owner
		}
		if changed("posting") {
			l.Posting = posting
		}
		if changed("members") {
			l.Members = splitList(members)
		}
		return s.PutList(ctx, l)
	})
	listFlags(set)
	for _, op := range []struct {
		use, alias, short string
		add               bool
	}{{"add-members <list> <address>...", "adlm", "Add members to a distribution list", true}, {"remove-members <list> <address>...", "rdlm", "Remove members from a distribution list", false}} {
		c := add(op.use, []string{op.alias}, op.short, 2, func(ctx context.Context, _ *cobra.Command, s *provision.Service, args []string) (any, error) {
			if op.add {
				return s.ChangeMembers(ctx, args[0], args[1:], nil)
			}
			return s.ChangeMembers(ctx, args[0], nil, args[1:])
		})
		c.Args = cobra.MinimumNArgs(2)
	}
	add("delete-list <address>", []string{"ddl"}, "Delete a distribution list", 1, func(ctx context.Context, _ *cobra.Command, s *provision.Service, args []string) (any, error) {
		if err := s.DeleteList(ctx, args[0]); err != nil {
			return nil, err
		}
		return map[string]string{"status": "distribution list deleted"}, nil
	})
	add("create-domain-alias <alias-domain> <domain>", []string{"cda"}, "Make every address at alias-domain deliver as the same name at domain (SMTP restart required)", 2, func(ctx context.Context, _ *cobra.Command, s *provision.Service, args []string) (any, error) {
		return s.DomainAlias(ctx, args[0], args[1], true)
	})
	add("delete-domain-alias <alias-domain>", []string{"dda"}, "Remove a domain alias and its local domain (SMTP restart required)", 1, func(ctx context.Context, _ *cobra.Command, s *provision.Service, args []string) (any, error) {
		return s.DomainAlias(ctx, args[0], "", false)
	})
	add("set-catch-all <domain> <address>", []string{"sca"}, `Deliver mail for unknown names in a domain to an address; "none" stops it`, 2, func(ctx context.Context, _ *cobra.Command, s *provision.Service, args []string) (any, error) {
		target := args[1]
		if strings.EqualFold(target, "none") {
			target = ""
		}
		return s.CatchAll(ctx, args[0], target)
	})
}

func printAddressing(w *tabwriter.Writer, value any) bool {
	switch v := value.(type) {
	case []mailpolicy.List:
		fmt.Fprintln(w, "LIST\tMEMBERS\tPOSTING\tOWNER\tNAME")
		for _, l := range v {
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\n", l.Address, l.MemberCount, l.Posting, l.Owner, l.Name)
		}
	case mailpolicy.List:
		owner := v.Owner
		if owner == "" {
			owner = "(none; bounces are dropped)"
		}
		fmt.Fprintf(w, "List:\t%s\nName:\t%s\nDescription:\t%s\nOwner:\t%s\nPosting:\t%s\nMembers:\t%d\n", v.Address, v.Name, v.Description, owner, v.Posting, len(v.Members))
		for _, m := range v.Members {
			fmt.Fprintf(w, "  %s\n", m)
		}
	case mailpolicy.DomainRoute:
		switch {
		case v.AliasOf != "" && v.CatchAll != "":
			fmt.Fprintf(w, "%s is an alias of %s; unknown names go to %s\n", v.Domain, v.AliasOf, v.CatchAll)
		case v.AliasOf != "":
			fmt.Fprintf(w, "%s is an alias of %s (SMTP restart required)\n", v.Domain, v.AliasOf)
		case v.CatchAll != "":
			fmt.Fprintf(w, "Unknown names at %s go to %s\n", v.Domain, v.CatchAll)
		default:
			fmt.Fprintf(w, "%s has no alias or catch-all\n", v.Domain)
		}
	default:
		return false
	}
	return true
}
