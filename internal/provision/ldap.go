package provision

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type LDAPConfig struct {
	URL, Base, BindDN, Password string
	SkipVerify                  bool
}
type LDAP struct {
	config    LDAPConfig
	addresses string
}

func NewLDAP(cfg LDAPConfig) (*LDAP, error) {
	if cfg.URL == "" || cfg.Base == "" || cfg.BindDN == "" || cfg.Password == "" {
		return nil, ErrUnavailable
	}
	dn, err := ldap.ParseDN(cfg.Base)
	if err != nil || len(dn.RDNs) < 2 {
		return nil, fmt.Errorf("%w: invalid mailbox LDAP base", ErrInvalid)
	}
	parent := (&ldap.DN{RDNs: dn.RDNs[1:]}).String()
	return &LDAP{config: cfg, addresses: "ou=mail-addresses," + parent}, nil
}
func (l *LDAP) connect(ctx context.Context) (*ldap.Conn, func(), error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if deadline, ok := ctx.Deadline(); ok {
		d.Deadline = deadline
	}
	c, err := ldap.DialURL(l.config.URL, ldap.DialWithDialer(d), ldap.DialWithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12,
		// #nosec G402 -- the operator's existing development-only certificate setting
		InsecureSkipVerify: l.config.SkipVerify}))
	if err != nil {
		return nil, nil, fmt.Errorf("mail directory connection failed: %w", err)
	}
	c.SetTimeout(20 * time.Second)
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	closeConn := func() { stop(); _ = c.Close() }
	if err = c.Bind(l.config.BindDN, l.config.Password); err != nil {
		closeConn()
		return nil, nil, fmt.Errorf("mail directory service bind failed: %w", err)
	}
	return c, closeConn, nil
}

var accountAttrs = []string{"mail", "uid", "cn", "displayName", "objectClass", "accountStatus", "mailQuotaSize", "mailAlternateAddress",
	"elemtaForwardTo", "elemtaForwardKeepCopy", "elemtaSendAs", "elemtaClassOfService", "createTimestamp", "modifyTimestamp"}

func entryAccount(e *ldap.Entry) (Account, error) {
	values := e.GetAttributeValues("mail")
	if len(values) != 1 {
		return Account{}, fmt.Errorf("%w: account must have exactly one primary mail address", ErrInvalid)
	}
	address, err := Address(values[0])
	if err != nil {
		return Account{}, err
	}
	name := e.GetAttributeValue("displayName")
	if name == "" {
		name = e.GetAttributeValue("cn")
	}
	status := strings.ToLower(e.GetAttributeValue("accountStatus"))
	if status == "" {
		status = "active"
	}
	if status != "active" && status != "suspended" {
		status = "disabled"
	}
	quota := int64(0)
	if value := e.GetAttributeValue("mailQuotaSize"); value != "" {
		quota, err = strconv.ParseInt(value, 10, 64)
		if err != nil || quota < 0 {
			return Account{}, fmt.Errorf("%w: directory contains an invalid quota", ErrInvalid)
		}
	}
	aliases := e.GetAttributeValues("mailAlternateAddress")
	if aliases == nil {
		aliases = []string{}
	}
	sort.Strings(aliases)
	return Account{Address: address, Name: name, Status: status, QuotaBytes: quota, Aliases: aliases,
		Forward: sortedLower(e.GetAttributeValues("elemtaForwardTo")), ForwardKeepCopy: strings.EqualFold(e.GetAttributeValue("elemtaForwardKeepCopy"), "TRUE"),
		SendAs: sortedLower(e.GetAttributeValues("elemtaSendAs")), DirectoryClass: e.GetAttributeValue("elemtaClassOfService"),
		Created: e.GetAttributeValue("createTimestamp"), Modified: e.GetAttributeValue("modifyTimestamp")}, nil
}

func sortedLower(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, strings.ToLower(v))
	}
	sort.Strings(out)
	return out
}
func (l *LDAP) find(c *ldap.Conn, address string) (*ldap.Entry, error) {
	res, err := c.Search(ldap.NewSearchRequest(l.config.Base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 15, false, "(&(objectClass=posixAccount)(mail="+ldap.EscapeFilter(address)+"))", accountAttrs, nil))
	if err != nil {
		return nil, err
	}
	if len(res.Entries) == 0 {
		return nil, ErrNotFound
	}
	if len(res.Entries) != 1 {
		return nil, fmt.Errorf("%w: primary address is ambiguous", ErrInvalid)
	}
	return res.Entries[0], nil
}
func (l *LDAP) List(ctx context.Context) ([]Account, error) {
	c, closeConn, err := l.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer closeConn()
	res, err := c.SearchWithPaging(ldap.NewSearchRequest(l.config.Base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 25001, 20, false, "(&(objectClass=posixAccount)(mail=*))", accountAttrs, nil), 500)
	if err != nil {
		return nil, err
	}
	if len(res.Entries) > 25000 {
		return nil, fmt.Errorf("mail directory exceeds the 25000-account listing limit")
	}
	out := make([]Account, 0, len(res.Entries))
	for _, e := range res.Entries {
		account, err := entryAccount(e)
		if err != nil {
			return nil, err
		}
		out = append(out, account)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out, nil
}
func (l *LDAP) Get(ctx context.Context, address string) (Account, error) {
	c, closeConn, err := l.connect(ctx)
	if err != nil {
		return Account{}, err
	}
	defer closeConn()
	e, err := l.find(c, address)
	if err != nil {
		return Account{}, err
	}
	return entryAccount(e)
}
func mapLDAP(err error) error {
	if ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) || ldap.IsErrorWithCode(err, ldap.LDAPResultAttributeOrValueExists) {
		return ErrExists
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return ErrNotFound
	}
	return err
}
func (l *LDAP) reserve(c *ldap.Conn, address, owner string) error {
	res, err := c.Search(ldap.NewSearchRequest(l.config.Base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 15, false, "(|(mail="+ldap.EscapeFilter(address)+")(mailAlternateAddress="+ldap.EscapeFilter(address)+"))", []string{"dn"}, nil))
	if err != nil {
		return err
	}
	if len(res.Entries) > 0 {
		return ErrExists
	}
	// A deterministic reservation DN makes uniqueness atomic across CLI and API
	// processes; a preflight directory search alone has a check/add race.
	ou := ldap.NewAddRequest(l.addresses, nil)
	ou.Attribute("objectClass", []string{"top", "organizationalUnit"})
	ou.Attribute("ou", []string{"mail-addresses"})
	if err = c.Add(ou); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
		return err
	}
	add := ldap.NewAddRequest("cn="+ldap.EscapeDN(address)+","+l.addresses, nil)
	add.Attribute("objectClass", []string{"top", "organizationalRole"})
	add.Attribute("cn", []string{address})
	add.Attribute("roleOccupant", []string{owner})
	return mapLDAP(c.Add(add))
}
func (l *LDAP) release(c *ldap.Conn, address, owner string) error {
	dn := "cn=" + ldap.EscapeDN(address) + "," + l.addresses
	res, err := c.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false, "(objectClass=organizationalRole)", []string{"roleOccupant"}, nil))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(res.Entries) != 1 {
		return errors.New("mail address reservation is ambiguous")
	}
	reserved, err := ldap.ParseDN(res.Entries[0].GetAttributeValue("roleOccupant"))
	if err != nil {
		return err
	}
	expected, err := ldap.ParseDN(owner)
	if err != nil {
		return err
	}
	if !reserved.EqualFold(expected) {
		return errors.New("mail address reservation belongs to another account")
	}
	return mapLDAP(c.Del(ldap.NewDelRequest(dn, nil)))
}
func (l *LDAP) Create(ctx context.Context, in Create) (Account, error) {
	c, closeConn, err := l.connect(ctx)
	if err != nil {
		return Account{}, err
	}
	defer closeConn()
	dn := "uid=" + ldap.EscapeDN(in.Address) + "," + l.config.Base
	if err = l.reserve(c, in.Address, dn); err != nil {
		return Account{}, err
	}
	add := ldap.NewAddRequest(dn, nil)
	for key, values := range map[string][]string{"objectClass": {"top", "inetOrgPerson", "posixAccount", "elemtaMailAccount"}, "uid": {in.Address}, "mail": {in.Address}, "cn": {in.Name}, "sn": {in.Name}, "displayName": {in.Name}, "uidNumber": {"5000"}, "gidNumber": {"5000"}, "homeDirectory": {"/var/mail/home/" + in.Address}, "accountStatus": {"disabled"}, "mailQuotaSize": {strconv.FormatInt(in.QuotaBytes, 10)}} {
		add.Attribute(key, values)
	}
	if err = c.Add(add); err != nil {
		_ = l.release(c, in.Address, dn)
		return Account{}, mapLDAP(err)
	}
	// Keep the new entry disabled until Password Modify has applied the
	// directory's own password policy. Never store a plaintext password attribute.
	if _, err = c.PasswordModify(ldap.NewPasswordModifyRequest(dn, "", in.Password)); err != nil {
		if cleanup := c.Del(ldap.NewDelRequest(dn, nil)); cleanup == nil {
			_ = l.release(c, in.Address, dn)
		}
		return Account{}, fmt.Errorf("directory refused initial password: %w", err)
	}
	change := ldap.NewModifyRequest(dn, nil)
	change.Replace("accountStatus", []string{"active"})
	if err = c.Modify(change); err != nil {
		return Account{}, fmt.Errorf("account exists but remains disabled: %w", err)
	}
	e, err := l.find(c, in.Address)
	if err != nil {
		return Account{}, err
	}
	return entryAccount(e)
}

// ensureMailAttrs makes sure the entry may hold the mail attributes: an
// account made outside Elemta may lack the class. (extensibleObject, which
// older versions used, allows them too; scripts/ldap-schema.sh moves those
// entries over.)
func ensureMailAttrs(e *ldap.Entry, change *ldap.ModifyRequest) {
	for _, class := range e.GetAttributeValues("objectClass") {
		if strings.EqualFold(class, "elemtaMailAccount") || strings.EqualFold(class, "extensibleObject") {
			return
		}
	}
	change.Add("objectClass", []string{"elemtaMailAccount"})
}
func (l *LDAP) Update(ctx context.Context, address string, p Patch) (Account, error) {
	c, closeConn, err := l.connect(ctx)
	if err != nil {
		return Account{}, err
	}
	defer closeConn()
	e, err := l.find(c, address)
	if err != nil {
		return Account{}, err
	}
	change := ldap.NewModifyRequest(e.DN, nil)
	if p.Name != nil {
		change.Replace("cn", []string{*p.Name})
		change.Replace("displayName", []string{*p.Name})
	}
	if p.Status != nil || p.QuotaBytes != nil || p.Forward != nil || p.ForwardKeepCopy != nil || p.SendAs != nil {
		ensureMailAttrs(e, change)
	}
	// Replace with no values removes the attribute.
	if p.Forward != nil {
		change.Replace("elemtaForwardTo", *p.Forward)
	}
	if p.ForwardKeepCopy != nil {
		change.Replace("elemtaForwardKeepCopy", []string{strings.ToUpper(strconv.FormatBool(*p.ForwardKeepCopy))})
	}
	if p.SendAs != nil {
		change.Replace("elemtaSendAs", *p.SendAs)
	}
	if p.Status != nil {
		change.Replace("accountStatus", []string{*p.Status})
	}
	if p.QuotaBytes != nil {
		change.Replace("mailQuotaSize", []string{strconv.FormatInt(*p.QuotaBytes, 10)})
	}
	if err = c.Modify(change); err != nil {
		return Account{}, mapLDAP(err)
	}
	e, err = l.find(c, address)
	if err != nil {
		return Account{}, err
	}
	return entryAccount(e)
}
func (l *LDAP) Alias(ctx context.Context, address, alias string, add bool) (Account, error) {
	c, closeConn, err := l.connect(ctx)
	if err != nil {
		return Account{}, err
	}
	defer closeConn()
	e, err := l.find(c, address)
	if err != nil {
		return Account{}, err
	}
	change := ldap.NewModifyRequest(e.DN, nil)
	if add {
		if err = l.reserve(c, alias, e.DN); err != nil {
			return Account{}, err
		}
		ensureMailAttrs(e, change)
		change.Add("mailAlternateAddress", []string{alias})
	} else {
		found := false
		for _, a := range e.GetAttributeValues("mailAlternateAddress") {
			if strings.EqualFold(a, alias) {
				found = true
			}
		}
		if !found {
			return Account{}, ErrNotFound
		}
		change.Delete("mailAlternateAddress", []string{alias})
	}
	if err = c.Modify(change); err != nil {
		if add {
			_ = l.release(c, alias, e.DN)
		}
		return Account{}, mapLDAP(err)
	}
	if !add {
		if err = l.release(c, alias, e.DN); err != nil {
			return Account{}, err
		}
	}
	e, err = l.find(c, address)
	if err != nil {
		return Account{}, err
	}
	return entryAccount(e)
}
func (l *LDAP) Delete(ctx context.Context, address string) error {
	c, closeConn, err := l.connect(ctx)
	if err != nil {
		return err
	}
	defer closeConn()
	e, err := l.find(c, address)
	if err != nil {
		return err
	}
	if err = c.Del(ldap.NewDelRequest(e.DN, nil)); err != nil {
		return mapLDAP(err)
	}
	for _, a := range append(e.GetAttributeValues("mailAlternateAddress"), address) {
		if err = l.release(c, a, e.DN); err != nil {
			return fmt.Errorf("account removed; address reservation cleanup failed: %w", err)
		}
	}
	return nil
}
