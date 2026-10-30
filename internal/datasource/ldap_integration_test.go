package datasource

import (
	"context"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

// TestLDAPPasswordsAreHashedByTheDirectory creates and updates a user on a
// real directory (docker/ldap), and checks the stored value and that the
// password binds. Set ELEMTA_TEST_LDAP_URL and ELEMTA_TEST_LDAP_ADMIN_PASSWORD
// to run it; it binds as cn=admin and removes the user.
func TestLDAPPasswordsAreHashedByTheDirectory(t *testing.T) {
	raw, pw := os.Getenv("ELEMTA_TEST_LDAP_URL"), os.Getenv("ELEMTA_TEST_LDAP_ADMIN_PASSWORD")
	if raw == "" || pw == "" {
		t.Skip("ELEMTA_TEST_LDAP_URL and ELEMTA_TEST_LDAP_ADMIN_PASSWORD not set")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	const admin = "cn=admin,dc=example,dc=com"
	l := NewLDAP(Config{Host: u.Hostname(), Port: port, Username: admin, Password: pw, Database: "dc=example,dc=com",
		Options: map[string]interface{}{"user_dn": "ou=people,dc=example,dc=com", "group_dn": "ou=groups,dc=example,dc=com", "tls_mode": "plaintext"}})
	if err := l.Connect(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	ctx := context.Background()
	name := "ds-" + uuid.NewString()[:8]
	dn := "uid=" + name + ",ou=people,dc=example,dc=com"
	if err := l.CreateUser(ctx, User{Username: name, FullName: "Kim Test", Email: name + "@example.com", Password: "first long password",
		Attributes: map[string]interface{}{"sn": "Test", "uidNumber": "42001", "gidNumber": "42001", "homeDirectory": "/nonexistent"}}); err != nil {
		t.Fatal(err)
	}
	direct, err := ldap.DialURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = direct.Close() }()
	if err := direct.Bind(admin, pw); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = direct.Del(ldap.NewDelRequest(dn, nil)) }()
	check := func(password string) {
		t.Helper()
		if err := direct.Bind(admin, pw); err != nil {
			t.Fatal(err)
		}
		found, err := direct.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(objectClass=*)", []string{"userPassword"}, nil))
		if err != nil || len(found.Entries) != 1 {
			t.Fatalf("search = %v", err)
		}
		if got := found.Entries[0].GetAttributeValue("userPassword"); !strings.HasPrefix(got, "{ARGON2}") {
			t.Fatalf("stored as %.12q", got)
		}
		if err := direct.Bind(dn, password); err != nil {
			t.Fatalf("password doesn't bind: %v", err)
		}
	}
	check("first long password")
	if err := l.UpdateUser(ctx, User{Username: name, Password: "second long password"}); err != nil {
		t.Fatal(err)
	}
	check("second long password")
}
