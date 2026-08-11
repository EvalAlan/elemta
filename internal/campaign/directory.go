package campaign

import (
	"fmt"
	"net/mail"
	"sort"
	"strings"
)

// DirectoryUser is the part of a directory account a campaign needs.
//
// Deliberately not datasource.User: a campaign has no business knowing about
// password hashes or group membership, and keeping the dependency out means
// this conversion is testable without standing up a directory.
type DirectoryUser struct {
	Email    string
	FullName string
	Username string
	IsActive bool
}

// RecipientsFromDirectory turns directory accounts into campaign recipients,
// and reports what it left out.
//
// Skipped accounts are returned rather than dropped, for the same reason
// ParseRecipients reports bad lines: an operator who imports 400 users and
// receives 380 recipients needs to know which twenty are missing and why.
// Silently shrinking the list is how somebody concludes they mailed everyone.
//
// Merge variables come from the directory so a template can address people by
// name without the operator building a CSV by hand.
func RecipientsFromDirectory(users []DirectoryUser) ([]Recipient, []string) {
	out := make([]Recipient, 0, len(users))
	seen := make(map[string]struct{}, len(users))
	var skipped []string

	for _, user := range users {
		label := strings.TrimSpace(user.Username)
		if label == "" {
			label = strings.TrimSpace(user.Email)
		}
		if label == "" {
			label = "(account with no username)"
		}

		// A disabled account is someone who has left or been suspended.
		// Mailing them is at best pointless and at worst a disclosure.
		if !user.IsActive {
			skipped = append(skipped, fmt.Sprintf("%s: account is not active", label))
			continue
		}

		address := strings.TrimSpace(user.Email)
		if address == "" {
			skipped = append(skipped, fmt.Sprintf("%s: no email address", label))
			continue
		}
		parsed, err := mail.ParseAddress(address)
		if err != nil {
			// Directories accumulate junk in the mail attribute. Better to name
			// it than to send something the queue will reject anyway.
			skipped = append(skipped, fmt.Sprintf("%s: %q is not a valid address", label, address))
			continue
		}

		key := strings.ToLower(parsed.Address)
		if _, duplicate := seen[key]; duplicate {
			// Aliases pointing at one mailbox are normal in a directory, so
			// this is not an error worth reporting — but it must not produce
			// two copies of the campaign.
			continue
		}
		seen[key] = struct{}{}

		vars := map[string]string{}
		if name := strings.TrimSpace(user.FullName); name != "" {
			vars["name"] = name
			// A template written against a CSV is more likely to use first_name.
			if first, _, found := strings.Cut(name, " "); found && first != "" {
				vars["first_name"] = first
			} else {
				vars["first_name"] = name
			}
		}
		if username := strings.TrimSpace(user.Username); username != "" {
			vars["username"] = username
		}
		if len(vars) == 0 {
			vars = nil
		}

		out = append(out, Recipient{Email: parsed.Address, Vars: vars})
	}

	// Same ordering guarantee as a pasted list, so a campaign built from a
	// directory sends in a stable, resumable order.
	SortRecipients(out)
	sort.Strings(skipped)
	return out, skipped
}
