package provision

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

// TestLDAPAccountMailSettings creates an account on a real directory with
// the current schema (docker/ldap) and sets its forwarding and send-as
// rights. Set ELEMTA_TEST_LDAP_URL and ELEMTA_TEST_LDAP_ADMIN_PASSWORD to
// run it; it binds as cn=admin and removes the account.
func TestLDAPAccountMailSettings(t *testing.T) {
	url, pw := os.Getenv("ELEMTA_TEST_LDAP_URL"), os.Getenv("ELEMTA_TEST_LDAP_ADMIN_PASSWORD")
	if url == "" || pw == "" {
		t.Skip("ELEMTA_TEST_LDAP_URL and ELEMTA_TEST_LDAP_ADMIN_PASSWORD not set")
	}
	l, err := NewLDAP(LDAPConfig{URL: url, Base: "ou=people,dc=example,dc=com", BindDN: "cn=admin,dc=example,dc=com", Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	address := "kim-" + uuid.NewString()[:8] + "@example.com"
	a, err := l.Create(ctx, Create{Address: address, Name: "Kim", Password: "long secure password"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Delete(context.Background(), address) })

	keep := true
	a, err = l.Update(ctx, address, Patch{Forward: &[]string{"far@remote.example"}, ForwardKeepCopy: &keep, SendAs: &[]string{"sales@example.com", "@brand.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(a.Forward, []string{"far@remote.example"}) || !a.ForwardKeepCopy || !slices.Equal(a.SendAs, []string{"@brand.example", "sales@example.com"}) {
		t.Errorf("account = %+v", a)
	}
	a, err = l.Update(ctx, address, Patch{Forward: &[]string{}, SendAs: &[]string{}})
	if err != nil || len(a.Forward) != 0 || len(a.SendAs) != 0 {
		t.Errorf("clearing: %+v %v", a, err)
	}

	// New accounts carry the account class, not extensibleObject.
	c, err := ldap.DialURL(url)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bind("cn=admin,dc=example,dc=com", pw); err != nil {
		t.Fatal(err)
	}
	res, err := c.Search(ldap.NewSearchRequest("ou=people,dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 5, false,
		"(mail="+ldap.EscapeFilter(address)+")", []string{"objectClass"}, nil))
	if err != nil || len(res.Entries) != 1 {
		t.Fatal(res, err)
	}
	classes := res.Entries[0].GetAttributeValues("objectClass")
	if !slices.Contains(classes, "elemtaMailAccount") || slices.Contains(classes, "extensibleObject") {
		t.Errorf("object classes = %v", classes)
	}
}
