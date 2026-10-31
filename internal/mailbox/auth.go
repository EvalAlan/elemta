package mailbox

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var ErrCredentials = errors.New("invalid mailbox credentials")

type Authenticator interface {
	Login(context.Context, string, string) (Account, error)
	Resolve(context.Context, string) (Account, error)
	// Exists reports whether the directory has an account with this
	// address, primary or alias, whatever its status. Resolve can't answer
	// that: it refuses disabled accounts like unknown ones.
	Exists(context.Context, string) (bool, error)
}
type LDAPAuth struct{ Config AuthConfig }

func (a LDAPAuth) dial() (*ldap.Conn, error) {
	u, err := url.Parse(a.Config.LDAPURL)
	if err != nil {
		return nil, err
	}
	c, err := ldap.DialURL(a.Config.LDAPURL, ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}), ldap.DialWithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}))
	if err != nil {
		return nil, err
	}
	c.SetTimeout(5 * time.Second)
	return c, nil
}
func (a LDAPAuth) lookup(ctx context.Context, address string, delivery bool) (Account, string, error) {
	if err := ctx.Err(); err != nil {
		return Account{}, "", err
	}
	address = strings.ToLower(strings.TrimSpace(address))
	if !strings.Contains(address, "@") && a.Config.DefaultDomain != "" {
		address += "@" + a.Config.DefaultDomain
	}
	if !strings.Contains(address, "@") || len(address) > 320 {
		return Account{}, "", ErrCredentials
	}
	c, err := a.bound()
	if err != nil {
		return Account{}, "", err
	}
	defer c.Close()
	escaped := ldap.EscapeFilter(address)
	filter := strings.Replace(a.Config.LDAPFilter, "%s", escaped, 1)
	if delivery {
		filter = "(&(objectClass=posixAccount)(|(mail=" + escaped + ")(mailAlternateAddress=" + escaped + ")))"
	}
	result, err := c.Search(ldap.NewSearchRequest(a.Config.LDAPBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 5, false, filter,
		[]string{"entryUUID", "mail", "accountStatus", "mailQuotaSize", "elemtaForwardTo", "elemtaForwardKeepCopy", "elemtaSendAs", "mailAlternateAddress", "elemtaClassOfService"}, nil))
	if err != nil {
		return Account{}, "", err
	}
	if len(result.Entries) != 1 {
		return Account{}, "", ErrCredentials
	}
	entry := result.Entries[0]
	allowed, suspended := statusAllows(entry.GetAttributeValue("accountStatus"), delivery)
	if !allowed {
		return Account{}, "", ErrCredentials
	}
	account := Account{ID: entry.GetAttributeValue("entryUUID"), Address: strings.ToLower(entry.GetAttributeValue("mail")), Suspended: suspended}
	if account.ID == "" || account.Address == "" {
		return Account{}, "", ErrCredentials
	}
	if q := entry.GetAttributeValue("mailQuotaSize"); q != "" {
		account.Quota, err = strconv.ParseInt(q, 10, 64)
		if err != nil || account.Quota < 0 {
			return Account{}, "", errors.New("invalid directory quota")
		}
	}
	account.Forward = lowerAll(entry.GetAttributeValues("elemtaForwardTo"))
	account.ForwardKeepCopy = strings.EqualFold(entry.GetAttributeValue("elemtaForwardKeepCopy"), "TRUE")
	account.SendAs = lowerAll(entry.GetAttributeValues("elemtaSendAs"))
	account.Aliases = lowerAll(entry.GetAttributeValues("mailAlternateAddress"))
	account.DirectoryClass = strings.TrimSpace(entry.GetAttributeValue("elemtaClassOfService"))
	return account, entry.DN, nil
}

// bound dials the directory and binds as the mailbox service's account.
func (a LDAPAuth) bound() (*ldap.Conn, error) {
	c, err := a.dial()
	if err != nil {
		return nil, err
	}
	dn, pw := os.Getenv(a.Config.BindDNEnv), os.Getenv(a.Config.BindPasswordEnv)
	if dn == "" || pw == "" {
		c.Close()
		return nil, errors.New("LDAP service credentials are required")
	}
	if err = c.Bind(dn, pw); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func lowerAll(values []string) []string {
	var out []string
	for _, v := range values {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			out = append(out, v)
		}
	}
	return out
}
func (a LDAPAuth) Login(ctx context.Context, user, password string) (Account, error) {
	if password == "" {
		return Account{}, ErrCredentials
	}
	account, dn, err := a.lookup(ctx, user, false)
	if err != nil {
		return Account{}, err
	}
	c, err := a.dial()
	if err != nil {
		return Account{}, err
	}
	defer c.Close()
	if err = c.Bind(dn, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return Account{}, ErrCredentials
		}
		return Account{}, err
	}
	return account, nil
}
func (a LDAPAuth) Resolve(ctx context.Context, address string) (Account, error) {
	account, _, err := a.lookup(ctx, address, true)
	return account, err
}

func (a LDAPAuth) Exists(ctx context.Context, address string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	c, err := a.dial()
	if err != nil {
		return false, err
	}
	defer c.Close()
	dn, pw := os.Getenv(a.Config.BindDNEnv), os.Getenv(a.Config.BindPasswordEnv)
	if dn == "" || pw == "" {
		return false, errors.New("LDAP service credentials are required")
	}
	if err = c.Bind(dn, pw); err != nil {
		return false, err
	}
	result, err := c.Search(ldap.NewSearchRequest(a.Config.LDAPBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 5, false,
		"(|(mail="+ldap.EscapeFilter(strings.ToLower(address))+")(mailAlternateAddress="+ldap.EscapeFilter(strings.ToLower(address))+"))", []string{"dn"}, nil))
	if err != nil {
		return false, err
	}
	return len(result.Entries) > 0, nil
}

// statusAllows applies an account's directory status (accountStatus):
//
//	active (or none)  signs in and receives mail
//	suspended         receives mail but may not sign in, on any protocol
//	disabled, other   neither: mail to it is refused
//
// Suspension is for an account that must stop being used now (a leaked
// password, a departing employee, an unpaid bill) without its mail
// bouncing while that is sorted out.
func statusAllows(status string, delivery bool) (allowed, suspended bool) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "active":
		return true, false
	case "suspended":
		return delivery, true
	default:
		return false, false
	}
}
