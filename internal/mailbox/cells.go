package mailbox

// Cells: mailboxes split across independent groups of mailbox servers.
//
// One mailbox database has a ceiling: rows, writes a second, the time a
// restore takes. Past it, mailboxes are split into cells, each a complete
// mailbox service of its own (servers, Postgres, body storage), sized to
// what one database handles well. Nothing in a cell depends on another, so
// a cell's outage or restore touches only its own mailboxes, and growing
// is adding a cell.
//
// A router (router.go) sits in front of the cells and speaks every mailbox
// protocol (IMAP, POP3, ManageSieve, LMTP, the HTTP APIs), so mail apps,
// the webmail, the MTA and the admin console each still see one mailbox
// service. For each connection or request it finds the cell that holds the
// mailbox and passes everything through.
//
// Placement is by domain, in the directory: elemtaMailboxCell on the
// domain's entry. A domain's mailboxes live together because so much is
// shared within one (shared folders, calendar sharing and free/busy,
// resources, lists, the domain's policy and routes), and none of that
// reaches across cells. An account may carry its own elemtaMailboxCell,
// which overrides its domain's: that is how one mailbox is moved (see
// MoveAccount), and how a domain too big for one cell is spread, with the
// cost that sharing between its cells doesn't work. Anything without a
// placement is in the default cell, so a single-cell deployment needs no
// placement at all.

import (
	"context"
	"errors"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

const (
	// cellAttribute names the cell on a domain or account entry
	// (docker/ldap/10-mail-schema.ldif).
	cellAttribute = "elemtaMailboxCell"
)

// CellOf returns the cell that holds address's mailbox, or "" for the
// default cell. An address the directory doesn't know is in its domain's
// cell, where it will be refused, or in the default cell.
func (a LDAPAuth) CellOf(ctx context.Context, address string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	address = strings.ToLower(strings.TrimSpace(address))
	if !strings.Contains(address, "@") && a.Config.DefaultDomain != "" {
		address += "@" + a.Config.DefaultDomain
	}
	key := "c:" + address
	if e, ok := a.cache.get(key); ok {
		return e.dn, nil
	}
	var cell string
	err := a.withService(func(c *ldap.Conn) error {
		var err error
		cell, err = a.cellOf(c, address)
		return err
	})
	if err != nil {
		return "", err
	}
	// Kept as an answer either way: "default cell" is as much an answer
	// as a name, and the address may well exist.
	a.cache.put(key, cached{dn: cell, ok: true})
	return cell, nil
}

func (a LDAPAuth) cellOf(c *ldap.Conn, address string) (string, error) {
	escaped := ldap.EscapeFilter(address)
	res, err := c.Search(ldap.NewSearchRequest(a.Config.LDAPBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 5, false,
		"(|(mail="+escaped+")(mailAlternateAddress="+escaped+"))", []string{cellAttribute}, nil))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return "", err
	}
	if res != nil && len(res.Entries) == 1 {
		if cell := strings.TrimSpace(res.Entries[0].GetAttributeValue(cellAttribute)); cell != "" {
			return cell, nil
		}
	}
	_, domain, _ := strings.Cut(address, "@")
	return a.domainCell(c, domain, 0)
}

// domainCell is the cell of domain's entry. An alias domain's mailboxes
// are its target's, so without a cell of its own it follows the alias.
func (a LDAPAuth) domainCell(c *ldap.Conn, domain string, depth int) (string, error) {
	if domain == "" || depth > 3 {
		return "", nil
	}
	res, err := c.Search(ldap.NewSearchRequest(a.directoryBase(), ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 5, false,
		"(&(objectClass=elemtaMailDomain)(elemtaDomainName="+ldap.EscapeFilter(domain)+"))", []string{cellAttribute, "elemtaAliasDomainOf"}, nil))
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return "", nil
		}
		return "", err
	}
	if len(res.Entries) != 1 {
		return "", nil
	}
	e := res.Entries[0]
	if cell := strings.TrimSpace(e.GetAttributeValue(cellAttribute)); cell != "" {
		return cell, nil
	}
	if target := strings.ToLower(strings.TrimSpace(e.GetAttributeValue("elemtaAliasDomainOf"))); target != "" && target != domain {
		return a.domainCell(c, target, depth+1)
	}
	return "", nil
}

// SetCell places one account in cell ("" returns it to its domain's).
// MoveAccount calls it once the copy is complete.
func (a LDAPAuth) SetCell(ctx context.Context, address, cell string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	address = strings.ToLower(strings.TrimSpace(address))
	err := a.withService(func(c *ldap.Conn) error {
		escaped := ldap.EscapeFilter(address)
		res, err := c.Search(ldap.NewSearchRequest(a.Config.LDAPBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 5, false,
			"(mail="+escaped+")", []string{"objectClass", cellAttribute}, nil))
		if err != nil {
			return err
		}
		if len(res.Entries) != 1 {
			return ErrNotFound
		}
		e := res.Entries[0]
		m := ldap.NewModifyRequest(e.DN, nil)
		hasClass := false
		for _, oc := range e.GetAttributeValues("objectClass") {
			if strings.EqualFold(oc, "elemtaMailboxPlacement") {
				hasClass = true
			}
		}
		switch {
		case cell == "" && e.GetAttributeValue(cellAttribute) == "":
			return nil
		case cell == "":
			m.Delete(cellAttribute, nil)
		default:
			if !hasClass {
				m.Add("objectClass", []string{"elemtaMailboxPlacement"})
			}
			m.Replace(cellAttribute, []string{cell})
		}
		return c.Modify(m)
	})
	if err == nil {
		a.cache.put("c:"+address, cached{dn: cell, ok: true})
	}
	return err
}

// errNoCell is a placement naming a cell the router doesn't know.
var errNoCell = errors.New("mailbox placed in an unknown cell")
