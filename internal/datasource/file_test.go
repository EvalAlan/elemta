package datasource

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestModifyUsersFileSerializesIndependentWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users")
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := ModifyUsersFile(path, func(users map[string]FileUser) error {
				users[strconv.Itoa(i)] = FileUser{Hash: "hash", Roles: []string{"user"}}
				return nil
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	users, err := ReadUsersFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 20 {
		t.Fatalf("retained %d of 20 independent updates", len(users))
	}
}

func TestModifyUsersFileRejectsEscapingLockSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "users")
	if err := os.Symlink(outside, path+".lock"); err != nil {
		t.Fatal(err)
	}
	if err := ModifyUsersFile(path, func(map[string]FileUser) error {
		t.Fatal("change ran with an escaping lock path")
		return nil
	}); err == nil {
		t.Fatal("escaping lock path was accepted")
	}
	content, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "unchanged" {
		t.Fatalf("outside file changed: %q", content)
	}
}

func newFileSource(t *testing.T, content string) (*FileDataSource, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	ds := NewFile(Config{Options: map[string]interface{}{"file": path}}).(*FileDataSource)
	if err := ds.Connect(); err != nil {
		t.Fatal(err)
	}
	return ds, path
}

// The stored bcrypt hash must not itself work as a password.
func TestFileAuthenticateRejectsTheHashAsPassword(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("right-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	ds, _ := newFileSource(t, "alice:"+string(hash)+":user\n")
	ctx := context.Background()

	if ok, _ := ds.Authenticate(ctx, "alice", "right-password"); !ok {
		t.Error("correct password refused")
	}
	if ok, _ := ds.Authenticate(ctx, "alice", string(hash)); ok {
		t.Error("the stored hash was accepted as the password; anyone who reads the users file could log in")
	}
}

func TestFileRolesAndLegacyLines(t *testing.T) {
	ds, _ := newFileSource(t, "ops:h1:operator\nsiteadmin:h2\nbob:h3\n")
	ctx := context.Background()

	for name, want := range map[string]string{"ops": "operator", "siteadmin": "admin", "bob": "user"} {
		u, err := ds.GetUser(ctx, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(u.Groups) != 1 || u.Groups[0] != want {
			t.Errorf("%s: roles %v, want [%s]", name, u.Groups, want)
		}
		if u.IsAdmin != (want == "admin") {
			t.Errorf("%s: IsAdmin = %v", name, u.IsAdmin)
		}
	}
}

func TestFileWritesPersistAndKeepOtherLines(t *testing.T) {
	ds, path := newFileSource(t, "old:h0\n")
	ctx := context.Background()

	if err := ds.CreateUser(ctx, User{Username: "new", Password: "h1", Groups: []string{"operator"}}); err != nil {
		t.Fatal(err)
	}
	if err := ds.CreateUser(ctx, User{Username: "new", Password: "h2"}); err != ErrAlreadyExists {
		t.Errorf("duplicate create: %v, want ErrAlreadyExists", err)
	}
	if err := ds.UpdateUser(ctx, User{Username: "new", Password: "h3", Groups: []string{"admin"}}); err != nil {
		t.Fatal(err)
	}

	users, err := ReadUsersFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := users["new"]; got.Hash != "h3" || len(got.Roles) != 1 || got.Roles[0] != "admin" {
		t.Errorf("new = %+v", got)
	}
	if got := users["old"]; got.Hash != "h0" || len(got.Roles) != 0 {
		t.Errorf("an untouched legacy line was rewritten: %+v", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("users file mode %o, want 600", info.Mode().Perm())
	}

	if err := ds.DeleteUser(ctx, "new"); err != nil {
		t.Fatal(err)
	}
	if _, err := ds.GetUser(ctx, "new"); err != ErrNotFound {
		t.Errorf("deleted user still found: %v", err)
	}
}

// A change written by another process (the CLI) is picked up on the next read.
func TestFileReloadsOnChange(t *testing.T) {
	ds, path := newFileSource(t, "a:h1:user\n")
	ctx := context.Background()

	if err := WriteUsersFile(path, map[string]FileUser{"b": {Hash: "h2", Roles: []string{"user"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := ds.GetUser(ctx, "b"); err != nil {
		t.Errorf("account added on disk not seen: %v", err)
	}
	if _, err := ds.GetUser(ctx, "a"); err != ErrNotFound {
		t.Errorf("account removed on disk still present: %v", err)
	}
}
