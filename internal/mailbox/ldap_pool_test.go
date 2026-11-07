package mailbox

import (
	"context"
	"errors"
	"fmt"
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

func TestLDAPCache(t *testing.T) {
	c := newLDAPCache(30 * time.Second)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	c.put("d:a@x", cached{account: Account{ID: "1", Forward: []string{"f@y"}}, ok: true})
	c.put("d:gone@x", cached{})
	e, ok := c.get("d:a@x")
	if !ok || e.account.ID != "1" {
		t.Fatal("a fresh answer wasn't kept")
	}
	e.account.Forward[0] = "changed"
	if again, _ := c.get("d:a@x"); again.account.Forward[0] != "f@y" {
		t.Error("changing what the cache returned changed the cache")
	}
	now = now.Add(11 * time.Second)
	if _, ok := c.get("d:gone@x"); ok {
		t.Error("'no such address' was kept past ten seconds")
	}
	if _, ok := c.get("d:a@x"); !ok {
		t.Error("an answer was dropped before its time")
	}
	now = now.Add(20 * time.Second)
	if _, ok := c.get("d:a@x"); ok {
		t.Error("an answer was kept past its time")
	}
	if c.password("a@x", "one") == c.password("a@x", "two") || c.password("a@x", "one") != c.password("a@x", "one") {
		t.Error("password keys don't tell passwords apart")
	}
	if newLDAPCache(0) != nil || newLDAPCache(-1) != nil {
		t.Error("caching can't be turned off")
	}
	var off *ldapCache
	off.put("k", cached{ok: true})
	if _, ok := off.get("k"); ok {
		t.Error("a nil cache remembered something")
	}
}

// TestLDAPPoolAndCache runs sign-ins and lookups against a real directory
// (docker/ldap, as TestLDAPDirectoryMail): connections are reused rather
// than opened per request, accepted passwords are remembered and wrong
// ones never are, and a directory restart costs no failed request.
// ELEMTA_TEST_LDAP_CONTAINER names the directory's container to restart.
func TestLDAPPoolAndCache(t *testing.T) {
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
	// Closed after the cleanups below that use it (cleanups run last first).
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Bind(admin, pw); err != nil {
		t.Fatal(err)
	}
	tag := uuid.NewString()[:8]
	address := "pool-" + tag + "@example.com"
	dn := "uid=" + address + ",ou=people," + base
	req := ldap.NewAddRequest(dn, nil)
	for k, v := range map[string][]string{
		"objectClass": {"inetOrgPerson", "posixAccount", "elemtaMailAccount"}, "uid": {address}, "mail": {address},
		"cn": {"Pool"}, "sn": {"Pool"}, "uidNumber": {"5001"}, "gidNumber": {"5001"}, "homeDirectory": {"/x"},
		"accountStatus": {"active"}, "userPassword": {"right-" + tag},
	} {
		req.Attribute(k, v)
	}
	if err := c.Add(req); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Del(ldap.NewDelRequest(dn, nil)) })

	a := NewLDAPAuth(AuthConfig{LDAPURL: url, LDAPBase: "ou=people," + base, LDAPFilter: "(&(objectClass=posixAccount)(mail=%s))",
		BindDNEnv: "TEST_LDAP_BIND_DN", BindPasswordEnv: "TEST_LDAP_BIND_PW", CacheSeconds: 30})
	ctx := context.Background()

	// Many deliveries to many addresses: a handful of connections.
	for i := range 200 {
		if _, err := a.Resolve(ctx, address); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Resolve(ctx, "nobody-"+tag+"-"+string(rune('a'+i%26))+"@example.com"); !errors.Is(err, ErrCredentials) {
			t.Fatalf("unknown address: %v", err)
		}
	}
	if a.search.opened > 2 {
		t.Errorf("400 lookups opened %d connections", a.search.opened)
	}
	if a.cache.hits < 370 {
		t.Errorf("cache hits = %d of 400 repeated lookups", a.cache.hits)
	}

	// The right password is checked once, then remembered.
	for range 5 {
		if _, err := a.Login(ctx, address, "right-"+tag); err != nil {
			t.Fatal(err)
		}
	}
	if a.binds.opened != 1 {
		t.Errorf("five sign-ins opened %d password connections", a.binds.opened)
	}
	// A wrong one is refused every time, and never remembered.
	for range 3 {
		if _, err := a.Login(ctx, address, "wrong"); !errors.Is(err, ErrCredentials) {
			t.Fatalf("wrong password: %v", err)
		}
	}
	// A refused bind leaves the connection usable for the next.
	if a.binds.opened != 1 {
		t.Errorf("wrong passwords opened %d password connections", a.binds.opened)
	}
	// With caching off, the directory decides every time.
	uncached := NewLDAPAuth(AuthConfig{LDAPURL: url, LDAPBase: "ou=people," + base, LDAPFilter: "(&(objectClass=posixAccount)(mail=%s))",
		BindDNEnv: "TEST_LDAP_BIND_DN", BindPasswordEnv: "TEST_LDAP_BIND_PW", CacheSeconds: -1})
	if _, err := uncached.Login(ctx, address, "right-"+tag); err != nil {
		t.Fatal(err)
	}
	if uncached.cache != nil {
		t.Error("cache_seconds = -1 still caches")
	}

	container := os.Getenv("ELEMTA_TEST_LDAP_CONTAINER")
	if container == "" {
		return
	}
	// The directory restarts: pooled connections are dead, and the next
	// request finds out, opens a new one and succeeds.
	if out, err := exec.Command("docker", "restart", container).CombinedOutput(); err != nil {
		t.Fatalf("restart: %v %s", err, out)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		probe, err := ldap.DialURL(url)
		if err == nil {
			err = probe.Bind(admin, pw)
			probe.Close()
		}
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the directory didn't come back")
		}
		time.Sleep(200 * time.Millisecond)
	}
	fresh := "nobody-else-" + tag + "@example.com" // not cached
	if _, err := a.Resolve(ctx, fresh); !errors.Is(err, ErrCredentials) {
		t.Fatalf("lookup after a directory restart: %v", err)
	}
	if ok, err := a.Exists(ctx, address); err != nil || !ok {
		t.Fatalf("exists after a directory restart: %v %v", ok, err)
	}
}

// TestLDAPLoad measures sign-ins a second against a real directory: the
// old way (a new connection for every request), pooled connections, and
// pooled with the cache. A measurement, run only with ELEMTA_LDAP_LOAD set
// to a number of sign-ins.
func TestLDAPLoad(t *testing.T) {
	url, pw := os.Getenv("ELEMTA_TEST_LDAP_URL"), os.Getenv("ELEMTA_TEST_LDAP_ADMIN_PASSWORD")
	n, _ := strconv.Atoi(os.Getenv("ELEMTA_LDAP_LOAD"))
	if url == "" || pw == "" || n == 0 {
		t.Skip("set ELEMTA_TEST_LDAP_URL, ELEMTA_TEST_LDAP_ADMIN_PASSWORD and ELEMTA_LDAP_LOAD")
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
	// 50 users signing in over and over, as phones and the webmail do.
	tag := uuid.NewString()[:8]
	var users []string
	for i := range 50 {
		address := fmt.Sprintf("load%d-%s@example.com", i, tag)
		dn := "uid=" + address + ",ou=people," + base
		req := ldap.NewAddRequest(dn, nil)
		for k, v := range map[string][]string{
			"objectClass": {"inetOrgPerson", "posixAccount", "elemtaMailAccount"}, "uid": {address}, "mail": {address},
			"cn": {"L"}, "sn": {"L"}, "uidNumber": {"5002"}, "gidNumber": {"5002"}, "homeDirectory": {"/x"}, "userPassword": {"pw-" + tag},
		} {
			req.Attribute(k, v)
		}
		if err := c.Add(req); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Del(ldap.NewDelRequest(dn, nil)) })
		users = append(users, address)
	}
	cfg := AuthConfig{LDAPURL: url, LDAPBase: "ou=people," + base, LDAPFilter: "(&(objectClass=posixAccount)(mail=%s))",
		BindDNEnv: "TEST_LDAP_BIND_DN", BindPasswordEnv: "TEST_LDAP_BIND_PW"}
	uncachedCfg, cachedCfg := cfg, cfg
	uncachedCfg.CacheSeconds, cachedCfg.CacheSeconds = -1, 30
	for _, run := range []struct {
		name string
		auth LDAPAuth
	}{{"new connection each time", LDAPAuth{Config: cfg}}, {"pooled", NewLDAPAuth(uncachedCfg)}, {"pooled and cached", NewLDAPAuth(cachedCfg)}} {
		const workers = 16
		jobs := make(chan string)
		var wg sync.WaitGroup
		var failed atomic.Int64
		start := time.Now()
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for u := range jobs {
					if _, err := run.auth.Login(context.Background(), u, "pw-"+tag); err != nil {
						failed.Add(1)
					}
				}
			}()
		}
		for i := range n {
			jobs <- users[i%len(users)]
		}
		close(jobs)
		wg.Wait()
		took := time.Since(start)
		fmt.Fprintf(os.Stderr, "LDAP-LOAD %-26s %6.0f sign-ins/s (%d failed)\n", run.name, float64(n)/took.Seconds(), failed.Load())
		if failed.Load() > 0 {
			t.Errorf("%s: %d sign-ins failed", run.name, failed.Load())
		}
	}
}
