package datasource

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

// TestLDAPConcurrentSignIns signs in from many SMTP sessions at once over
// the one shared connection, as submission does, with the race detector
// watching, and (with ELEMTA_TEST_LDAP_CONTAINER naming the directory's
// container) through a directory restart: once it is back, sign-ins work
// again without the MTA restarting.
func TestLDAPConcurrentSignIns(t *testing.T) {
	raw, pw := os.Getenv("ELEMTA_TEST_LDAP_URL"), os.Getenv("ELEMTA_TEST_LDAP_ADMIN_PASSWORD")
	if raw == "" || pw == "" {
		t.Skip("ELEMTA_TEST_LDAP_URL and ELEMTA_TEST_LDAP_ADMIN_PASSWORD not set")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	const admin = "cn=admin,dc=example,dc=com"
	l := NewLDAP(Config{Host: u.Hostname(), Port: port, Username: admin, Password: pw, Database: "dc=example,dc=com",
		Options: map[string]interface{}{"user_dn": "ou=people,dc=example,dc=com", "group_dn": "ou=groups,dc=example,dc=com", "tls_mode": "plaintext"}})
	if err := l.Connect(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	ctx := context.Background()
	name := "cc-" + uuid.NewString()[:8]
	if err := l.CreateUser(ctx, User{Username: name, FullName: "Con Current", Email: name + "@example.com", Password: "a long enough password",
		Attributes: map[string]interface{}{"sn": "Current", "uidNumber": "42002", "gidNumber": "42002", "homeDirectory": "/nonexistent"}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if c, err := ldap.DialURL(raw); err == nil {
			_ = c.Bind(admin, pw)
			_ = c.Del(ldap.NewDelRequest("uid="+name+",ou=people,dc=example,dc=com", nil))
			_ = c.Close()
		}
	})
	burst := func() int64 {
		var wg sync.WaitGroup
		var failed atomic.Int64
		for range 32 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 10 {
					if ok, err := l.Authenticate(ctx, name, "a long enough password"); err != nil || !ok {
						failed.Add(1)
					}
				}
			}()
		}
		wg.Wait()
		return failed.Load()
	}
	if n := burst(); n != 0 {
		t.Fatalf("%d of 320 concurrent sign-ins failed", n)
	}
	if ok, _ := l.Authenticate(ctx, name, "wrong"); ok {
		t.Fatal("a wrong password signed in")
	}
	container := os.Getenv("ELEMTA_TEST_LDAP_CONTAINER")
	if container == "" {
		return
	}
	if out, err := exec.Command("docker", "restart", container).CombinedOutput(); err != nil {
		t.Fatalf("restart: %v %s", err, out)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		probe, err := ldap.DialURL(raw)
		if err == nil {
			err = probe.Bind(admin, pw)
			_ = probe.Close()
		}
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the directory didn't come back")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if n := burst(); n != 0 {
		t.Fatalf("%d of 320 sign-ins failed after the directory restarted", n)
	}
}
