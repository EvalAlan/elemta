package datasource

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// FileDataSource implements DataSource over the users file that `elemta user`
// and the dashboard's Users page manage.
//
// Format, one account per line:
//
//	username:bcrypt-hash[:role[,role...]]
//
// The role field is optional so that files written before it existed keep
// working; an account without one gets LegacyRolesFor(username). A bcrypt hash
// never contains a colon, so the third field is unambiguous.
//
// The file is re-read whenever its modification time or size changes, so an
// account added, changed or removed with the CLI applies to a running server
// on its next request instead of after a restart.
type FileDataSource struct {
	path      string
	users     map[string]FileUser
	info      os.FileInfo // what was last read; compared to spot changes
	connected bool
	mu        sync.RWMutex
}

// FileUser is one account in the users file.
type FileUser struct {
	Hash  string
	Roles []string // empty means "not recorded": LegacyRolesFor applies
}

// EffectiveRoles returns the roles the account actually has.
func (u FileUser) EffectiveRoles(username string) []string {
	if len(u.Roles) > 0 {
		return append([]string(nil), u.Roles...)
	}
	return LegacyRolesFor(username)
}

// LegacyRolesFor is the role given to an account whose line records none. It
// reproduces how the file datasource assigned roles before roles were stored:
// any name containing "admin" was an administrator. New accounts always have
// their role written down, so this only governs files from older releases.
func LegacyRolesFor(username string) []string {
	if strings.Contains(username, "admin") {
		return []string{"admin"}
	}
	return []string{"user"}
}

func NewFile(config Config) DataSource {
	path, _ := config.Options["file"].(string)
	// If path is empty, try the db_path key as well
	if path == "" {
		path, _ = config.Options["db_path"].(string)
	}
	return &FileDataSource{path: path, users: make(map[string]FileUser)}
}

func (f *FileDataSource) Connect() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.path == "" {
		return fmt.Errorf("file path is empty")
	}
	info, err := os.Stat(f.path)
	if err != nil {
		return fmt.Errorf("failed to open user file %s: %w", f.path, err)
	}
	users, err := ReadUsersFile(f.path)
	if err != nil {
		return err
	}
	f.users = users
	f.info = info
	f.connected = true
	return nil
}

// refresh re-reads the file if it changed since it was last read. A file that
// has become unreadable keeps the last good set of accounts rather than
// locking everyone out; removing an account is done by rewriting the file, not
// by deleting it.
func (f *FileDataSource) refresh() {
	info, err := os.Stat(f.path)
	if err != nil {
		return
	}
	f.mu.RLock()
	unchanged := sameFileVersion(f.info, info)
	f.mu.RUnlock()
	if unchanged {
		return
	}
	users, err := ReadUsersFile(f.path)
	if err != nil {
		return
	}
	f.mu.Lock()
	f.users = users
	f.info = info
	f.mu.Unlock()
}

// sameFileVersion reports whether b is the file a was. Writers replace the file
// by rename, so a new inode is the reliable signal; a password change keeps the
// size (bcrypt hashes are fixed length) and can land inside the same mtime tick.
func sameFileVersion(a, b os.FileInfo) bool {
	return a != nil && os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size()
}

func (f *FileDataSource) Close() error      { f.connected = false; return nil }
func (f *FileDataSource) IsConnected() bool { return f.connected }
func (f *FileDataSource) Name() string      { return "file" }
func (f *FileDataSource) Type() string      { return "file" }

func (f *FileDataSource) Authenticate(ctx context.Context, username, password string) (bool, error) {
	f.refresh()
	f.mu.RLock()
	u, ok := f.users[username]
	f.mu.RUnlock()
	if !ok {
		return false, ErrNotFound
	}

	// A bcrypt hash is only ever checked as a hash. Comparing the submitted
	// password to the stored string as well would let anyone who has read the
	// users file log in by pasting the hash.
	if strings.HasPrefix(u.Hash, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(password)) == nil, nil
	}

	// LDAP-style hashes are not supported here; refuse rather than compare the
	// hash text.
	if strings.HasPrefix(u.Hash, "{") {
		return false, nil
	}

	// Legacy plaintext entry, written by hand before `elemta user` existed.
	return subtle.ConstantTimeCompare([]byte(u.Hash), []byte(password)) == 1, nil
}

func (f *FileDataSource) GetUser(ctx context.Context, username string) (User, error) {
	f.refresh()
	f.mu.RLock()
	defer f.mu.RUnlock()
	u, ok := f.users[username]
	if !ok {
		return User{}, ErrNotFound
	}
	return fileUserToUser(username, u), nil
}

func fileUserToUser(username string, u FileUser) User {
	roles := u.EffectiveRoles(username)
	isAdmin := false
	for _, r := range roles {
		if r == "admin" {
			isAdmin = true
		}
	}
	return User{
		Username: username,
		Password: u.Hash,
		IsActive: true,
		IsAdmin:  isAdmin,
		Groups:   roles,
	}
}

func (f *FileDataSource) ListUsers(ctx context.Context, filter map[string]interface{}, limit, offset int) ([]User, error) {
	f.refresh()
	f.mu.RLock()
	defer f.mu.RUnlock()
	names := make([]string, 0, len(f.users))
	for name := range f.users {
		names = append(names, name)
	}
	sort.Strings(names)
	users := make([]User, 0, len(names))
	for _, name := range names {
		users = append(users, fileUserToUser(name, f.users[name]))
	}
	return users, nil
}

// CreateUser adds an account. user.Password must already be hashed.
func (f *FileDataSource) CreateUser(ctx context.Context, user User) error {
	return f.modify(func(users map[string]FileUser) error {
		if _, exists := users[user.Username]; exists {
			return ErrAlreadyExists
		}
		users[user.Username] = FileUser{Hash: user.Password, Roles: rolesFor(user)}
		return nil
	})
}

// UpdateUser replaces an account's hash and roles. user.Password must already
// be hashed.
func (f *FileDataSource) UpdateUser(ctx context.Context, user User) error {
	return f.modify(func(users map[string]FileUser) error {
		if _, exists := users[user.Username]; !exists {
			return ErrNotFound
		}
		users[user.Username] = FileUser{Hash: user.Password, Roles: rolesFor(user)}
		return nil
	})
}

func (f *FileDataSource) DeleteUser(ctx context.Context, username string) error {
	return f.modify(func(users map[string]FileUser) error {
		if _, exists := users[username]; !exists {
			return ErrNotFound
		}
		delete(users, username)
		return nil
	})
}

// rolesFor records the roles a User carries. A user with no groups but the
// admin flag set is an administrator; with neither, a standard user.
func rolesFor(user User) []string {
	if len(user.Groups) > 0 {
		return append([]string(nil), user.Groups...)
	}
	if user.IsAdmin {
		return []string{"admin"}
	}
	return []string{"user"}
}

// modify applies change to the accounts as they are on disk now, not as they
// were last read, and writes the result back. Reading first means an edit
// made with the CLI since the last request is not overwritten.
func (f *FileDataSource) modify(change func(map[string]FileUser) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.path == "" {
		return fmt.Errorf("file path is empty")
	}
	users, err := ReadUsersFile(f.path)
	if err != nil {
		return err
	}
	if err := change(users); err != nil {
		return err
	}
	if err := WriteUsersFile(f.path, users); err != nil {
		return err
	}
	f.users = users
	if info, err := os.Stat(f.path); err == nil {
		f.info = info
	}
	return nil
}

func (f *FileDataSource) Query(ctx context.Context, query string, args ...interface{}) (interface{}, error) {
	return nil, ErrNotSupported
}

// ReadUsersFile loads a users file. A missing file is an empty set, so the
// first account can create it.
func ReadUsersFile(path string) (map[string]FileUser, error) {
	users := make(map[string]FileUser)

	file, err := os.Open(path) // #nosec G304 -- operator-configured users file
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return users, nil
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 || parts[0] == "" {
			continue
		}
		u := FileUser{Hash: parts[1]}
		if len(parts) == 3 {
			for _, r := range strings.Split(parts[2], ",") {
				if r = strings.TrimSpace(r); r != "" {
					u.Roles = append(u.Roles, r)
				}
			}
		}
		users[parts[0]] = u
	}
	return users, scanner.Err()
}

// WriteUsersFile rewrites a users file atomically and readable only by its
// owner: it holds password hashes.
func WriteUsersFile(path string, users map[string]FileUser) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}

	names := make([]string, 0, len(users))
	for name := range users {
		names = append(names, name)
	}
	sort.Strings(names)

	var sb strings.Builder
	sb.WriteString("# Elemta API/web users. One username:bcrypt-hash:role per line.\n")
	sb.WriteString("# Managed by `elemta user` and the dashboard's Users page.\n")
	for _, name := range names {
		u := users[name]
		sb.WriteString(name)
		sb.WriteString(":")
		sb.WriteString(u.Hash)
		if len(u.Roles) > 0 {
			sb.WriteString(":")
			sb.WriteString(strings.Join(u.Roles, ","))
		}
		sb.WriteString("\n")
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
