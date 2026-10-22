package mailbox

// The company address book (global address list): the accounts and
// distribution lists of a user's own domain, for the webmail's address
// autocomplete. It is served on the security API with the user's own
// credentials and covers only their domain, so one tenant never sees
// another's people.

import (
	"context"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// DirectoryEntry is one address in the address book.
type DirectoryEntry struct {
	Address string `json:"address"`
	Name    string `json:"name,omitempty"`
	Kind    string `json:"kind"` // "account" or "list"
}

// DirectoryLister is an Authenticator that can list a domain's active
// accounts. It is separate from Authenticator so that one that can't (a
// test double) still works, with lists only.
type DirectoryLister interface {
	Directory(ctx context.Context, domain string) ([]DirectoryEntry, error)
}

// maxDirectory bounds one domain's address book; past it the autocomplete
// would be no help anyway.
const maxDirectory = 5000

// Directory lists a domain's active accounts from LDAP.
func (a LDAPAuth) Directory(ctx context.Context, domain string) ([]DirectoryEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, err := a.dial()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	dn, pw := os.Getenv(a.Config.BindDNEnv), os.Getenv(a.Config.BindPasswordEnv)
	if dn == "" || pw == "" {
		return nil, errors.New("LDAP service credentials are required")
	}
	if err := c.Bind(dn, pw); err != nil {
		return nil, err
	}
	filter := "(&(objectClass=posixAccount)(mail=*@" + ldap.EscapeFilter(domain) + "))"
	res, err := c.Search(ldap.NewSearchRequest(a.Config.LDAPBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, maxDirectory, 10, false, filter, []string{"mail", "cn", "displayName", "accountStatus"}, nil))
	if err != nil && (res == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded)) {
		return nil, err
	}
	var out []DirectoryEntry
	for _, e := range res.Entries {
		// Suspended accounts still receive mail, so colleagues can still
		// find them; disabled ones can't.
		if ok, _ := statusAllows(e.GetAttributeValue("accountStatus"), true); !ok {
			continue
		}
		name := e.GetAttributeValue("displayName")
		if name == "" {
			name = e.GetAttributeValue("cn")
		}
		out = append(out, DirectoryEntry{Address: strings.ToLower(e.GetAttributeValue("mail")), Name: name, Kind: "account"})
	}
	// The domain's lists kept in the directory (elemtaMailList).
	res, err = c.Search(ldap.NewSearchRequest(a.directoryBase(), ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, maxDirectory, 10, false,
		"(&(objectClass=elemtaMailList)(mail=*@"+ldap.EscapeFilter(domain)+"))", []string{"mail", "cn", "displayName"}, nil))
	if err != nil && (res == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded)) {
		return nil, err
	}
	for _, e := range res.Entries {
		name := e.GetAttributeValue("displayName")
		if name == "" {
			name = e.GetAttributeValue("cn")
		}
		out = append(out, DirectoryEntry{Address: strings.ToLower(e.GetAttributeValue("mail")), Name: name, Kind: "list"})
	}
	return out, nil
}

// directoryCache keeps each domain's address book for a few minutes: the
// webmail asks on every compose, and a new colleague a few minutes late is
// fine.
type directoryCache struct {
	mu      sync.Mutex
	domains map[string]directoryCached
}

type directoryCached struct {
	entries []DirectoryEntry
	at      time.Time
}

const directoryTTL = 5 * time.Minute

// directory returns the address book of address's domain.
func (s *Service) directory(ctx context.Context, address string) ([]DirectoryEntry, error) {
	i := strings.LastIndexByte(address, '@')
	if i < 0 {
		return nil, errors.New("directory: account has no domain")
	}
	domain := strings.ToLower(address[i+1:])
	s.dir.mu.Lock()
	cached, ok := s.dir.domains[domain]
	s.dir.mu.Unlock()
	if ok && time.Since(cached.at) < directoryTTL {
		return cached.entries, nil
	}
	var entries []DirectoryEntry
	if lister, ok := s.auth.(DirectoryLister); ok {
		accounts, err := lister.Directory(ctx, domain)
		if err != nil {
			return nil, err
		}
		entries = append(entries, accounts...)
	}
	lists, err := s.engine.Lists(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Address] = true
	}
	for _, l := range lists {
		// A directory list hides a database list with its address.
		if strings.HasSuffix(l.Address, "@"+domain) && !seen[l.Address] {
			entries = append(entries, DirectoryEntry{Address: l.Address, Name: l.Name, Kind: "list"})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Address < entries[j].Address })
	if entries == nil {
		entries = []DirectoryEntry{}
	}
	s.dir.mu.Lock()
	if s.dir.domains == nil {
		s.dir.domains = map[string]directoryCached{}
	}
	s.dir.domains[domain] = directoryCached{entries: entries, at: time.Now()}
	s.dir.mu.Unlock()
	return entries, nil
}
