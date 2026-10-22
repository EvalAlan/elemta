package mailbox

// Mail settings the directory carries, for organisations that run their
// people in their own directory (docs/directory.md):
//
//   - on an account (elemtaMailAccount): forwarding, the addresses it may
//     send as, and its class of service;
//   - distribution lists as directory groups (elemtaMailList), with member
//     DNs and member addresses;
//   - domains (elemtaMailDomain): a catch-all address, the domain it is an
//     alias of, and the domain's class of service.
//
// The mailbox database keeps its own lists, domain routes and class
// assignments, managed from the dashboard. Where the directory says
// something it wins; where it says nothing the database decides. So a
// directory list hides a database list with the same address, a directory
// domain's catch-all replaces the database's, and the classes stack: the
// database's domain class, then the directory's domain class, then the
// directory's account class, then a class the dashboard set on the account,
// which is the administrator's explicit override.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/go-ldap/ldap/v3"
)

// DirectoryDomain is a domain's entry in the directory.
type DirectoryDomain struct {
	Domain, CatchAll, AliasOf, Class string
}

// MailDirectory is an Authenticator whose directory also holds lists and
// domains. It is separate from Authenticator so that one without them (a
// test double) still works, with the database's alone.
type MailDirectory interface {
	DirectoryList(ctx context.Context, address string) (mailpolicy.List, bool, error)
	DirectoryDomain(ctx context.Context, domain string) (DirectoryDomain, bool, error)
}

// maxListMemberEntries bounds the member DNs read for one directory list.
const maxListMemberEntries = 5000

// DirectoryList returns the list whose address or alias is address.
func (a LDAPAuth) DirectoryList(ctx context.Context, address string) (mailpolicy.List, bool, error) {
	if err := ctx.Err(); err != nil {
		return mailpolicy.List{}, false, err
	}
	address = strings.ToLower(strings.TrimSpace(address))
	c, err := a.bound()
	if err != nil {
		return mailpolicy.List{}, false, err
	}
	defer c.Close()
	escaped := ldap.EscapeFilter(address)
	res, err := c.Search(ldap.NewSearchRequest(a.Config.LDAPBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 5, false,
		"(&(objectClass=elemtaMailList)(|(mail="+escaped+")(mailAlternateAddress="+escaped+")))",
		[]string{"mail", "cn", "displayName", "description", "elemtaListOwner", "elemtaListPosting", "elemtaListMember", "member"}, nil))
	if err != nil {
		return mailpolicy.List{}, false, err
	}
	switch len(res.Entries) {
	case 0:
		return mailpolicy.List{}, false, nil
	case 1:
	default:
		return mailpolicy.List{}, false, fmt.Errorf("two directory lists claim %s", address)
	}
	e := res.Entries[0]
	l := mailpolicy.List{
		Address:     strings.ToLower(e.GetAttributeValue("mail")),
		Name:        e.GetAttributeValue("displayName"),
		Description: e.GetAttributeValue("description"),
		Owner:       strings.ToLower(strings.TrimSpace(e.GetAttributeValue("elemtaListOwner"))),
		Posting:     listPosting(e.GetAttributeValue("elemtaListPosting")),
	}
	if l.Name == "" {
		l.Name = e.GetAttributeValue("cn")
	}
	members := lowerAll(e.GetAttributeValues("elemtaListMember"))
	dns := e.GetAttributeValues("member")
	if len(dns) > maxListMemberEntries {
		dns = dns[:maxListMemberEntries]
	}
	// Member DNs are people (or other lists); what the list delivers to is
	// their address. A DN that no longer exists, or has no address, is
	// skipped: refint normally removes those.
	for _, dn := range dns {
		r, err := c.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(objectClass=*)", []string{"mail"}, nil))
		if err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				continue
			}
			return mailpolicy.List{}, false, err
		}
		if len(r.Entries) == 1 {
			if m := strings.ToLower(strings.TrimSpace(r.Entries[0].GetAttributeValue("mail"))); m != "" {
				members = append(members, m)
			}
		}
	}
	slices.Sort(members)
	members = slices.Compact(members)
	l.Members = slices.DeleteFunc(members, func(m string) bool { return m == l.Address })
	l.MemberCount = len(l.Members)
	return l, true, nil
}

// listPosting reads a directory list's posting policy. Unset is open, as
// for a list made in the dashboard; a value that isn't one of the policies
// is read as members-only rather than guessed open.
func listPosting(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch {
	case v == "":
		return mailpolicy.PostAnyone
	case slices.Contains(mailpolicy.PostingPolicies, v):
		return v
	default:
		return mailpolicy.PostMembers
	}
}

// DirectoryDomain returns a domain's directory entry.
func (a LDAPAuth) DirectoryDomain(ctx context.Context, domain string) (DirectoryDomain, bool, error) {
	if err := ctx.Err(); err != nil {
		return DirectoryDomain{}, false, err
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	c, err := a.bound()
	if err != nil {
		return DirectoryDomain{}, false, err
	}
	defer c.Close()
	res, err := c.Search(ldap.NewSearchRequest(a.Config.LDAPBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 5, false,
		"(&(objectClass=elemtaMailDomain)(elemtaDomainName="+ldap.EscapeFilter(domain)+"))",
		[]string{"elemtaCatchAll", "elemtaAliasDomainOf", "elemtaClassOfService"}, nil))
	if err != nil {
		return DirectoryDomain{}, false, err
	}
	if len(res.Entries) == 0 {
		return DirectoryDomain{}, false, nil
	}
	e := res.Entries[0]
	return DirectoryDomain{
		Domain:   domain,
		CatchAll: strings.ToLower(strings.TrimSpace(e.GetAttributeValue("elemtaCatchAll"))),
		AliasOf:  strings.ToLower(strings.TrimSpace(e.GetAttributeValue("elemtaAliasDomainOf"))),
		Class:    strings.TrimSpace(e.GetAttributeValue("elemtaClassOfService")),
	}, true, nil
}

// directoryMailTTL is how long this replica reuses a domain's entry and an
// account's directory class: they are read on every delivery and sign-in,
// and change rarely. A change in the directory takes effect within it.
const directoryMailTTL = 30 * time.Second

type directoryMail struct {
	mu      sync.Mutex
	domains map[string]cachedDomain
	classes map[string]cachedClass
}

type cachedDomain struct {
	at     time.Time
	domain DirectoryDomain
}

type cachedClass struct {
	at    time.Time
	class string
}

func (s *Service) mailDirectory() MailDirectory {
	md, _ := s.auth.(MailDirectory)
	return md
}

// directoryDomain returns the domain's directory entry, or an empty one.
func (s *Service) directoryDomain(ctx context.Context, domain string) (DirectoryDomain, error) {
	md := s.mailDirectory()
	if md == nil {
		return DirectoryDomain{}, nil
	}
	domain = strings.ToLower(domain)
	now := time.Now()
	s.dirMail.mu.Lock()
	if c, ok := s.dirMail.domains[domain]; ok && now.Sub(c.at) < directoryMailTTL {
		s.dirMail.mu.Unlock()
		return c.domain, nil
	}
	s.dirMail.mu.Unlock()
	d, _, err := md.DirectoryDomain(ctx, domain)
	if err != nil {
		return DirectoryDomain{}, err
	}
	s.dirMail.mu.Lock()
	if s.dirMail.domains == nil || len(s.dirMail.domains) > 10000 {
		s.dirMail.domains = map[string]cachedDomain{}
	}
	s.dirMail.domains[domain] = cachedDomain{at: now, domain: d}
	s.dirMail.mu.Unlock()
	return d, nil
}

// route is a domain's routing: the database's, with the directory's catch-all
// and alias in place of it where the directory sets them.
func (s *Service) route(ctx context.Context, domain string) (mailpolicy.DomainRoute, error) {
	r, err := s.engine.Route(ctx, domain)
	if err != nil {
		return r, err
	}
	d, err := s.directoryDomain(ctx, domain)
	if err != nil {
		return r, err
	}
	if d.CatchAll != "" {
		r.CatchAll = d.CatchAll
	}
	if d.AliasOf != "" && d.AliasOf != r.Domain {
		r.AliasOf = d.AliasOf
	}
	return r, nil
}

// directoryList returns the directory's list for an address, or nil.
func (s *Service) directoryList(ctx context.Context, address string) (*mailpolicy.List, error) {
	md := s.mailDirectory()
	if md == nil {
		return nil, nil
	}
	l, ok, err := md.DirectoryList(ctx, address)
	if err != nil || !ok {
		return nil, err
	}
	return &l, nil
}

// list returns the list an address names: the directory's, or else the
// database's.
func (s *Service) list(ctx context.Context, address string) (mailpolicy.List, error) {
	l, err := s.directoryList(ctx, address)
	if err != nil {
		return mailpolicy.List{}, err
	}
	if l != nil {
		return *l, nil
	}
	return s.engine.List(ctx, address)
}

// directoryClasses is the Engine's hook for the classes of service the
// directory assigns to an address's domain and to the account itself
// (EffectivePolicy). An address the directory doesn't resolve (a disabled
// or deleted account) has no account class.
func (s *Service) directoryClasses(ctx context.Context, address string) (domainClass, accountClass string, err error) {
	address = strings.ToLower(address)
	d, err := s.directoryDomain(ctx, domainOf(address))
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	s.dirMail.mu.Lock()
	c, ok := s.dirMail.classes[address]
	s.dirMail.mu.Unlock()
	if ok && now.Sub(c.at) < directoryMailTTL {
		return d.Class, c.class, nil
	}
	a, err := s.auth.Resolve(ctx, address)
	if err != nil && !errors.Is(err, ErrCredentials) {
		return "", "", err
	}
	s.dirMail.mu.Lock()
	if s.dirMail.classes == nil || len(s.dirMail.classes) > 100000 {
		s.dirMail.classes = map[string]cachedClass{}
	}
	s.dirMail.classes[address] = cachedClass{at: now, class: a.DirectoryClass}
	s.dirMail.mu.Unlock()
	return d.Class, a.DirectoryClass, nil
}

// sendAsAllowed reports whether the account's directory grants (an
// address, or @domain for a whole domain) cover address.
func sendAsAllowed(grants []string, address string) bool {
	address = strings.ToLower(strings.TrimSpace(address))
	if !strings.Contains(address, "@") {
		return false
	}
	for _, g := range grants {
		if g == address || (strings.HasPrefix(g, "@") && g[1:] == domainOf(address)) {
			return true
		}
	}
	return false
}

// forward sends a message on to the account's forwarding addresses and
// reports whether it should also be delivered here: when the directory
// asks for a copy, or when there was nowhere to forward it.
//
// It goes out the way a filter's redirect does (redirect), with the same
// retry record and loop marker: a message this account already forwarded
// that comes back is kept here instead of going round again. A class of
// service that forbids forwarding outside the server limits this too.
func (s *Service) forward(ctx context.Context, d delivery) (keep bool, err error) {
	if hasRedirectMark(d.raw, d.rcpt) {
		return true, nil
	}
	var targets []string
	for _, t := range d.account.Forward {
		if t == d.account.Address || t == strings.ToLower(d.rcpt) {
			continue
		}
		if p := d.account.Policy; p != nil && !p.ExternalForwarding {
			if _, err := s.auth.Resolve(ctx, t); err != nil {
				s.log.Info("directory forwarding outside the server refused by class of service", "account", d.account.ID)
				continue
			}
		}
		targets = append(targets, t)
	}
	if len(targets) == 0 {
		return true, nil
	}
	for _, t := range targets {
		if err := s.redirect(ctx, d, t); err != nil {
			return false, err
		}
	}
	return d.account.ForwardKeepCopy, nil
}
