package mailbox

import (
	"context"
	"os"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

// TestCellPlacement reads placements from a real directory (as
// TestLDAPDirectoryMail): an account's own cell beats its domain's, an
// alias domain follows its target, and anything unplaced is in the
// default cell. SetCell places an account and returns it.
func TestCellPlacement(t *testing.T) {
	url, pw := os.Getenv("ELEMTA_TEST_LDAP_URL"), os.Getenv("ELEMTA_TEST_LDAP_ADMIN_PASSWORD")
	if url == "" || pw == "" {
		t.Skip("ELEMTA_TEST_LDAP_URL and ELEMTA_TEST_LDAP_ADMIN_PASSWORD not set")
	}
	const base, admin = "dc=example,dc=com", "cn=admin,dc=example,dc=com"
	t.Setenv("TEST_LDAP_BIND_DN", admin)
	t.Setenv("TEST_LDAP_BIND_PW", pw)
	c, err := ldap.DialURL(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Bind(admin, pw); err != nil {
		t.Fatal(err)
	}
	tag := uuid.NewString()[:8]
	domain, alias, other := "d"+tag+".example", "alias"+tag+".example", "o"+tag+".example"
	add := func(dn string, attrs map[string][]string) {
		t.Helper()
		req := ldap.NewAddRequest(dn, nil)
		for k, v := range attrs {
			req.Attribute(k, v)
		}
		if err := c.Add(req); err != nil {
			t.Fatalf("add %s: %v", dn, err)
		}
		t.Cleanup(func() { _ = c.Del(ldap.NewDelRequest(dn, nil)) })
	}
	person := func(address string, cell string) {
		attrs := map[string][]string{
			"objectClass": {"inetOrgPerson", "posixAccount", "elemtaMailAccount"}, "uid": {address}, "mail": {address},
			"cn": {"P"}, "sn": {"P"}, "uidNumber": {"5003"}, "gidNumber": {"5003"}, "homeDirectory": {"/x"},
		}
		if cell != "" {
			attrs["objectClass"] = append(attrs["objectClass"], "elemtaMailboxPlacement")
			attrs["elemtaMailboxCell"] = []string{cell}
		}
		add("uid="+address+",ou=people,"+base, attrs)
	}
	add("elemtaDomainName="+domain+",ou=domains,"+base, map[string][]string{
		"objectClass": {"elemtaMailDomain", "elemtaMailboxPlacement"}, "elemtaDomainName": {domain}, "elemtaMailboxCell": {"east"}})
	add("elemtaDomainName="+alias+",ou=domains,"+base, map[string][]string{
		"objectClass": {"elemtaMailDomain"}, "elemtaDomainName": {alias}, "elemtaAliasDomainOf": {domain}})
	person("ann@"+domain, "")
	person("moved@"+domain, "west")
	person("zed@"+other, "")

	a := NewLDAPAuth(AuthConfig{LDAPURL: url, LDAPBase: "ou=people," + base, LDAPFilter: "(&(objectClass=posixAccount)(mail=%s))",
		BindDNEnv: "TEST_LDAP_BIND_DN", BindPasswordEnv: "TEST_LDAP_BIND_PW", CacheSeconds: -1})
	ctx := context.Background()
	for address, want := range map[string]string{
		"ann@" + domain:    "east", // the domain's cell
		"moved@" + domain:  "west", // its own
		"ann@" + alias:     "east", // an alias domain follows its target
		"nobody@" + domain: "east", // unknown, but the domain is placed
		"zed@" + other:     "",     // the default cell
		"@" + domain:       "east", // a domain on its own (the router's HTTP)
		"ANN@" + domain:    "east",
	} {
		got, err := a.CellOf(ctx, address)
		if err != nil || got != want {
			t.Errorf("CellOf(%s) = %q, %v; want %q", address, got, err, want)
		}
	}
	if err := a.SetCell(ctx, "zed@"+other, "north"); err != nil {
		t.Fatal(err)
	}
	if got, _ := a.CellOf(ctx, "zed@"+other); got != "north" {
		t.Errorf("after SetCell: %q", got)
	}
	if err := a.SetCell(ctx, "zed@"+other, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := a.CellOf(ctx, "zed@"+other); got != "" {
		t.Errorf("after clearing: %q", got)
	}
}
