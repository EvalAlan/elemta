package auth

import (
	"fmt"
	"sort"
	"strings"
)

// A domain administrator's domains are stored with their roles, as
// "domain:example.com" entries next to "domain-admin". That keeps them in
// whatever holds dashboard users (the users file, LDAP groups, SQL) with
// no second store to keep in step, and an entry that isn't a role name is
// ignored by every permission check.

// DomainScopePrefix marks a group entry naming a domain the user administers.
const DomainScopePrefix = "domain:"

// DomainScope returns the domains a user's groups assign, lowercased,
// sorted and without duplicates.
func DomainScope(groups []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range groups {
		if d, ok := strings.CutPrefix(g, DomainScopePrefix); ok {
			d = strings.ToLower(strings.TrimSpace(d))
			if d != "" && !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	sort.Strings(out)
	return out
}

// DomainAdminGroups is what to store for a domain administrator of domains.
// It refuses an empty set: a domain administrator with no domains can do
// nothing, which is a mistake rather than a setting.
func DomainAdminGroups(domains []string) ([]string, error) {
	groups := []string{"domain-admin"}
	seen := map[string]bool{}
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || seen[d] {
			continue
		}
		if !validScopeDomain(d) {
			return nil, fmt.Errorf("%q is not a domain name", d)
		}
		seen[d] = true
		groups = append(groups, DomainScopePrefix+d)
	}
	if len(groups) == 1 {
		return nil, fmt.Errorf("a domain administrator needs at least one domain")
	}
	sort.Strings(groups[1:])
	return groups, nil
}

// validScopeDomain accepts a plain DNS name. The users file separates roles
// with commas and fields with colons, and neither can appear here.
func validScopeDomain(d string) bool {
	if len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
