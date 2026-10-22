package webmail

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

// TestLDAPOwnMailSettings checks, on a real directory with the stack's
// access rules (scripts/ldap-service-accounts.sh applied), that a user can
// read their settings and change their own forwarding but not grant
// themselves send-as rights. Set ELEMTA_TEST_LDAP_URL and
// ELEMTA_TEST_LDAP_ADMIN_PASSWORD to run it.
func TestLDAPOwnMailSettings(t *testing.T) {
	url, pw := os.Getenv("ELEMTA_TEST_LDAP_URL"), os.Getenv("ELEMTA_TEST_LDAP_ADMIN_PASSWORD")
	if url == "" || pw == "" {
		t.Skip("ELEMTA_TEST_LDAP_URL and ELEMTA_TEST_LDAP_ADMIN_PASSWORD not set")
	}
	const admin = "cn=admin,dc=example,dc=com"
	c, err := ldap.DialURL(url)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bind(admin, pw); err != nil {
		t.Fatal(err)
	}
	user := "lee-" + uuid.NewString()[:8] + "@example.com"
	dn := "uid=" + user + ",ou=people,dc=example,dc=com"
	add := ldap.NewAddRequest(dn, nil)
	for k, v := range map[string][]string{"objectClass": {"inetOrgPerson", "posixAccount", "elemtaMailAccount"}, "uid": {user}, "mail": {user}, "cn": {"Lee"}, "sn": {"Lee"},
		"uidNumber": {"5000"}, "gidNumber": {"5000"}, "homeDirectory": {"/x"}, "elemtaSendAs": {"sales@example.com"}} {
		add.Attribute(k, v)
	}
	if err := c.Add(add); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Del(ldap.NewDelRequest(dn, nil)) })
	if _, err := c.PasswordModify(ldap.NewPasswordModifyRequest(dn, "", "user secret 1234")); err != nil {
		t.Fatal(err)
	}

	l := ldapPasswords{url: url, base: "ou=people,dc=example,dc=com", filter: "(&(objectClass=posixAccount)(mail=%s))", searchDN: admin, searchPassword: pw}
	ctx := context.Background()
	if err := l.SetForwarding(ctx, user, "user secret 1234", []string{"far@remote.example"}, true); err != nil {
		t.Fatal(err)
	}
	m, err := l.ReadMailSettings(ctx, user, "user secret 1234")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Forward, []string{"far@remote.example"}) || !m.KeepCopy || !slices.Equal(m.SendAs, []string{"sales@example.com"}) {
		t.Errorf("settings = %+v", m)
	}
	if err := l.SetForwarding(ctx, user, "user secret 1234", nil, false); err != nil {
		t.Fatalf("clearing: %v", err)
	}

	// Send-as rights are the administrator's to grant.
	uc, err := ldap.DialURL(url)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	if err := uc.Bind(dn, "user secret 1234"); err != nil {
		t.Fatal(err)
	}
	grab := ldap.NewModifyRequest(dn, nil)
	grab.Add("elemtaSendAs", []string{"ceo@example.com"})
	if err := uc.Modify(grab); !ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
		t.Errorf("a user granted themselves send-as: %v", err)
	}
}
