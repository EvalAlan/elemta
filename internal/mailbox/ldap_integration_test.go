package mailbox

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

// TestLDAPDirectoryMail reads the directory's mail entries from a real
// server with the current schema (docker/ldap): an account's forwarding,
// send-as and class, a list with member DNs and member addresses, and a
// domain. Set ELEMTA_TEST_LDAP_URL (for example ldap://127.0.0.1:13899)
// and ELEMTA_TEST_LDAP_ADMIN_PASSWORD to run it; it binds as cn=admin and
// removes what it creates.
func TestLDAPDirectoryMail(t *testing.T) {
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
	defer c.Close()
	if err := c.Bind(admin, pw); err != nil {
		t.Fatal(err)
	}
	tag := uuid.NewString()[:8]
	domain := "t" + tag + ".example"
	person := "uid=ana@" + domain + ",ou=people," + base
	list := "cn=crew-" + tag + ",ou=groups," + base
	dom := "elemtaDomainName=" + domain + ",ou=domains," + base
	add := func(dn string, attrs map[string][]string) {
		t.Helper()
		req := ldap.NewAddRequest(dn, nil)
		for k, v := range attrs {
			req.Attribute(k, v)
		}
		if err := c.Add(req); err != nil {
			t.Fatalf("add %s: %v", dn, err)
		}
	}
	t.Cleanup(func() {
		for _, dn := range []string{list, dom, person} {
			_ = c.Del(ldap.NewDelRequest(dn, nil))
		}
	})
	add(person, map[string][]string{
		"objectClass": {"inetOrgPerson", "posixAccount", "elemtaMailAccount"}, "uid": {"ana@" + domain}, "mail": {"ana@" + domain},
		"cn": {"Ana"}, "sn": {"Ana"}, "uidNumber": {"5000"}, "gidNumber": {"5000"}, "homeDirectory": {"/x"},
		"accountStatus": {"active"}, "elemtaForwardTo": {"Far@Remote.Example"}, "elemtaForwardKeepCopy": {"TRUE"},
		"elemtaSendAs": {"crew@" + domain, "@brand.example"}, "elemtaClassOfService": {"staff"},
	})
	add(list, map[string][]string{
		"objectClass": {"groupOfNames", "elemtaMailList"}, "cn": {"crew-" + tag}, "mail": {"crew@" + domain},
		"mailAlternateAddress": {"team@" + domain}, "member": {person}, "elemtaListMember": {"Out@Remote.Example"},
		"elemtaListPosting": {"members"}, "elemtaListOwner": {"ana@" + domain}, "displayName": {"Crew"},
	})
	add(dom, map[string][]string{
		"objectClass": {"elemtaMailDomain"}, "elemtaDomainName": {domain}, "elemtaCatchAll": {"ana@" + domain},
		"elemtaAliasDomainOf": {"main.example"}, "elemtaClassOfService": {"basic"},
	})

	// Configured as the stack is: accounts searched under ou=people, lists
	// and domains found beside it.
	a := LDAPAuth{Config: AuthConfig{LDAPURL: url, LDAPBase: "ou=people," + base, LDAPFilter: "(&(objectClass=posixAccount)(mail=%s))",
		BindDNEnv: "TEST_LDAP_BIND_DN", BindPasswordEnv: "TEST_LDAP_BIND_PW"}}
	ctx := context.Background()

	acct, err := a.Resolve(ctx, "ana@"+domain)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(acct.Forward, []string{"far@remote.example"}) || !acct.ForwardKeepCopy || acct.DirectoryClass != "staff" ||
		!slices.Equal(acct.SendAs, []string{"crew@" + domain, "@brand.example"}) {
		t.Errorf("account = %+v", acct)
	}

	// The list by its alias, its member DN read as an address.
	l, ok, err := a.DirectoryList(ctx, "team@"+domain)
	if err != nil || !ok {
		t.Fatalf("list: %v %v", ok, err)
	}
	if l.Address != "crew@"+domain || l.Name != "Crew" || l.Posting != "members" || l.Owner != "ana@"+domain ||
		!slices.Equal(l.Members, []string{"ana@" + domain, "out@remote.example"}) {
		t.Errorf("list = %+v", l)
	}
	if _, ok, err := a.DirectoryList(ctx, "nobody@"+domain); ok || err != nil {
		t.Errorf("a list that isn't there: %v %v", ok, err)
	}

	d, ok, err := a.DirectoryDomain(ctx, domain)
	if err != nil || !ok {
		t.Fatalf("domain: %v %v", ok, err)
	}
	if d.CatchAll != "ana@"+domain || d.AliasOf != "main.example" || d.Class != "basic" {
		t.Errorf("domain = %+v", d)
	}

	// The address book offers the directory's list with the account.
	book, err := a.Directory(ctx, domain)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, e := range book {
		kinds[e.Address] = e.Kind
	}
	if kinds["ana@"+domain] != "account" || kinds["crew@"+domain] != "list" {
		t.Errorf("address book = %+v", book)
	}

	// The memberof overlay follows groupOfNames.
	res, err := c.Search(ldap.NewSearchRequest(person, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(objectClass=*)", []string{"memberOf"}, nil))
	if err != nil || len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("memberOf") != list {
		t.Errorf("memberOf not maintained: %v %v", res, err)
	}
}
