// Package adminmfa keeps the admin console's second factors: an authenticator
// app with recovery codes, and passkeys, for each console user.
//
// Console users live in the users file, LDAP or SQL (internal/datasource),
// none of which has room for them, so they are kept in a file of their own
// beside the users file, readable only by the console, and written the same
// way: under a lock, to a temporary file, then renamed into place. A user's
// entry is keyed by their console username.
package adminmfa

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- TOTP (RFC 6238) is HMAC-SHA1, which authenticator apps expect
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	totpDigits    = 6
	totpPeriod    = 30
	recoveryCodes = 10
	maxPasskeys   = 10
	maxName       = 64
	maxFile       = 8 << 20
	// pendingLife is how long an authenticator set up but not confirmed
	// stays waiting.
	pendingLife = 15 * time.Minute
)

var (
	// ErrWrongCode is a code that isn't the app's current one or an unused
	// recovery code.
	ErrWrongCode = errors.New("that code isn't right")
	// ErrActive is setting up an authenticator while one is in use.
	ErrActive = errors.New("an authenticator app is already set up; turn it off first")
	// ErrNoPending is confirming an authenticator nobody started setting up.
	ErrNoPending = errors.New("start setting up the authenticator app again")
	// ErrPasskey is a passkey the server didn't accept.
	ErrPasskey = errors.New("the passkey wasn't accepted")
	// ErrInvalid is a request that can't be carried out as made.
	ErrInvalid = errors.New("invalid request")
)

// Store is the second-factor file.
type Store struct {
	path string
	mu   sync.Mutex
}

// Open returns the store at path. Nothing is read until it's used, and a
// missing file means nobody has a second factor yet.
func Open(path string) *Store { return &Store{path: path} }

// PathFor is where the store for a users file lives.
func PathFor(usersFile string) string { return usersFile + ".2fa" }

// Path is the store's file.
func (s *Store) Path() string { return s.path }

type file struct {
	Users map[string]*record `json:"users"`
}

type record struct {
	TOTP      string    `json:"totp,omitempty"`
	Pending   string    `json:"totp_pending,omitempty"`
	PendingAt time.Time `json:"totp_pending_at,omitzero"`
	LastStep  int64     `json:"totp_last_step,omitempty"`
	Recovery  []string  `json:"recovery,omitempty"` // sha256 of each unused code
	Passkeys  []passkey `json:"passkeys,omitempty"`
	NextID    int64     `json:"next_id,omitempty"`
}

func (r *record) empty() bool {
	return r.TOTP == "" && r.Pending == "" && len(r.Passkeys) == 0
}

type passkey struct {
	PasskeyInfo
	Credential webauthn.Credential `json:"credential"`
}

// PasskeyInfo is a passkey as its owner sees it.
type PasskeyInfo struct {
	ID       int64      `json:"id"`
	Name     string     `json:"name"`
	Host     string     `json:"host"`
	Created  time.Time  `json:"created"`
	LastUsed *time.Time `json:"last_used,omitempty"`
}

// Status is a user's second factors.
type Status struct {
	TOTP         bool          `json:"totp"`
	RecoveryLeft int           `json:"recovery_left"`
	Passkeys     []PasskeyInfo `json:"passkeys"`
}

// On reports whether the user must give a second factor to sign in.
func (st Status) On() bool { return st.TOTP || len(st.Passkeys) > 0 }

// Methods names the second factors the user can give.
func (st Status) Methods() []string {
	var m []string
	if st.TOTP {
		m = append(m, "totp")
	}
	if len(st.Passkeys) > 0 {
		m = append(m, "passkey")
	}
	return m
}

func (s *Store) load() (*file, error) {
	f := &file{Users: map[string]*record{}}
	fh, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = fh.Close() }()
	data, err := io.ReadAll(io.LimitReader(fh, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFile {
		return nil, fmt.Errorf("adminmfa: %s is too large", s.path)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return f, nil
	}
	if err := json.Unmarshal(data, f); err != nil {
		return nil, fmt.Errorf("adminmfa: %s: %w", s.path, err)
	}
	if f.Users == nil {
		f.Users = map[string]*record{}
	}
	return f, nil
}

// view reads the file. It takes the same lock as a change, so it never
// sees one half written.
func (s *Store) view(fn func(*file) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	f, err := s.load()
	if err != nil {
		return err
	}
	return fn(f)
}

// update reads the file, applies fn and writes it back. The lock file keeps
// the CLI and the console from writing over each other's changes.
func (s *Store) update(fn func(*file) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	f, err := s.load()
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		return err
	}
	for name, r := range f.Users {
		if r.empty() {
			delete(f.Users, name)
		}
	}
	data, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".2fa-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	s.keepOwner(tmp)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

func (s *Store) lock() (func(), error) {
	// #nosec G304 -- the path is the operator's users file with a fixed suffix
	lf, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	s.keepOwner(lf)
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil { // #nosec G115 -- a file descriptor fits an int
		_ = lf.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN) // #nosec G115 -- as above
		_ = lf.Close()
	}, nil
}

// keepOwner gives a file the console's owner when root writes it, as the
// CLI may: a file the console can't read stops everyone signing in.
func (s *Store) keepOwner(f *os.File) {
	if os.Geteuid() != 0 {
		return
	}
	for _, p := range []string{s.path, strings.TrimSuffix(s.path, ".2fa"), filepath.Dir(s.path)} {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			_ = f.Chown(int(st.Uid), int(st.Gid))
		}
		return
	}
}

func (f *file) user(name string) *record {
	r := f.Users[name]
	if r == nil {
		r = &record{}
		f.Users[name] = r
	}
	return r
}

// Status returns a user's second factors.
func (s *Store) Status(user string) (Status, error) {
	st := Status{Passkeys: []PasskeyInfo{}}
	err := s.view(func(f *file) error {
		r := f.Users[user]
		if r == nil {
			return nil
		}
		st.TOTP = r.TOTP != ""
		if st.TOTP {
			st.RecoveryLeft = len(r.Recovery)
		}
		for _, p := range r.Passkeys {
			st.Passkeys = append(st.Passkeys, p.PasskeyInfo)
		}
		return nil
	})
	return st, err
}

// Users lists the users with a second factor.
func (s *Store) Users() (map[string]bool, error) {
	out := map[string]bool{}
	err := s.view(func(f *file) error {
		for name, r := range f.Users {
			if r.TOTP != "" || len(r.Passkeys) > 0 {
				out[name] = true
			}
		}
		return nil
	})
	return out, err
}

// Reset removes every second factor a user has, for someone who lost their
// device, or a user removed from the console.
func (s *Store) Reset(user string) error {
	has := false
	if err := s.view(func(f *file) error {
		has = f.Users[user] != nil
		return nil
	}); err != nil || !has {
		return err
	}
	return s.update(func(f *file) error {
		delete(f.Users, user)
		return nil
	})
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// BeginTOTP makes a new authenticator secret, pending until ConfirmTOTP
// shows the user's app has it, and returns it with the otpauth URI apps
// scan.
func (s *Store) BeginTOTP(user, issuer string) (secret, uri string, err error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	secret = b32.EncodeToString(raw)
	err = s.update(func(f *file) error {
		r := f.user(user)
		if r.TOTP != "" {
			return ErrActive
		}
		r.Pending, r.PendingAt = secret, time.Now().UTC()
		return nil
	})
	if err != nil {
		return "", "", err
	}
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return secret, "otpauth://totp/" + url.PathEscape(issuer+":"+user) + "?" + q.Encode(), nil
}

// ConfirmTOTP turns the pending secret on when code matches it, and returns
// new recovery codes, shown once.
func (s *Store) ConfirmTOTP(user, code string, now time.Time) ([]string, error) {
	plain, hashed, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	err = s.update(func(f *file) error {
		r := f.user(user)
		if r.TOTP != "" {
			return ErrActive
		}
		if r.Pending == "" || now.Sub(r.PendingAt) > pendingLife {
			r.Pending = ""
			return ErrNoPending
		}
		key, err := b32.DecodeString(r.Pending)
		if err != nil {
			return ErrNoPending
		}
		step, ok := matchTOTP(key, normalizeCode(code), now, 0)
		if !ok {
			return ErrWrongCode
		}
		r.TOTP, r.Pending, r.PendingAt, r.LastStep, r.Recovery = r.Pending, "", time.Time{}, step, hashed
		return nil
	})
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// DisableTOTP turns the authenticator app off, with its recovery codes.
func (s *Store) DisableTOTP(user string) error {
	return s.update(func(f *file) error {
		if r := f.Users[user]; r != nil {
			r.TOTP, r.Pending, r.PendingAt, r.LastStep, r.Recovery = "", "", time.Time{}, 0, nil
		}
		return nil
	})
}

// NewRecoveryCodes replaces a user's recovery codes, when they've used or
// lost them.
func (s *Store) NewRecoveryCodes(user string) ([]string, error) {
	plain, hashed, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	err = s.update(func(f *file) error {
		r := f.Users[user]
		if r == nil || r.TOTP == "" {
			return ErrInvalid
		}
		r.Recovery = hashed
		return nil
	})
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// VerifyCode checks a sign-in code: the app's current code, used once, or an
// unused recovery code, which is then used up.
func (s *Store) VerifyCode(user, code string, now time.Time) (recovery bool, err error) {
	code = normalizeCode(code)
	err = s.update(func(f *file) error {
		r := f.Users[user]
		if r == nil || r.TOTP == "" || code == "" {
			return ErrWrongCode
		}
		if key, err := b32.DecodeString(r.TOTP); err == nil {
			if step, ok := matchTOTP(key, code, now, r.LastStep); ok {
				r.LastStep = step
				return nil
			}
		}
		h := secretHash(code)
		for i, c := range r.Recovery {
			if hmac.Equal([]byte(c), []byte(h)) {
				r.Recovery = slices.Delete(r.Recovery, i, i+1)
				recovery = true
				return nil
			}
		}
		return ErrWrongCode
	})
	return recovery, err
}

func newRecoveryCodes() (plain, hashed []string, err error) {
	for range recoveryCodes {
		c, err := randomLetters(16)
		if err != nil {
			return nil, nil, err
		}
		plain = append(plain, groupBy4(c))
		hashed = append(hashed, secretHash(c))
	}
	return plain, hashed, nil
}

// totpCode is the RFC 4226 HOTP value for a time step.
func totpCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) // #nosec G115 -- time steps are positive
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, v%1000000)
}

// matchTOTP finds the step a code belongs to, allowing a step of clock
// drift either way, and refuses steps at or before last so a code works once.
func matchTOTP(secret []byte, code string, now time.Time, last int64) (int64, bool) {
	if len(code) != totpDigits {
		return 0, false
	}
	step := now.Unix() / totpPeriod
	for _, st := range []int64{step, step - 1, step + 1} {
		if st > last && hmac.Equal([]byte(totpCode(secret, st)), []byte(code)) {
			return st, true
		}
	}
	return 0, false
}

func normalizeCode(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == ' ' || r == '-' || r == '\t':
			return -1
		case r >= 'A' && r <= 'Z':
			return r + 'a' - 'A'
		}
		return r
	}, s)
}

// secretHash stores recovery codes: 16 random letters are 75 bits, so a fast
// hash is enough.
func secretHash(s string) string {
	sum := sha256.Sum256([]byte(normalizeCode(s)))
	return hex.EncodeToString(sum[:])
}

func randomLetters(n int) (string, error) {
	b := make([]byte, n)
	for i := range b {
		v, err := rand.Int(rand.Reader, big.NewInt(26))
		if err != nil {
			return "", err
		}
		b[i] = "abcdefghijklmnopqrstuvwxyz"[v.Int64()]
	}
	return string(b), nil
}

func groupBy4(s string) string {
	var parts []string
	for len(s) > 4 {
		parts = append(parts, s[:4])
		s = s[4:]
	}
	return strings.Join(append(parts, s), "-")
}

// ---- passkeys ----------------------------------------------------------------

// userHandle names a console user to authenticators: a hash, so it says
// nothing about who it is and fits WebAuthn's 64 bytes.
func userHandle(user string) []byte {
	sum := sha256.Sum256([]byte("elemta-console-user:" + user))
	return sum[:]
}

type webUser struct {
	name        string
	credentials []webauthn.Credential
}

func (u webUser) WebAuthnID() []byte                         { return userHandle(u.name) }
func (u webUser) WebAuthnName() string                       { return u.name }
func (u webUser) WebAuthnDisplayName() string                { return u.name }
func (u webUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// RelyingParty is the site passkeys belong to: the host the console was
// reached at. Only localhost may be plain HTTP, as browsers require.
func RelyingParty(host, origin string) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() != host || host == "" || u.Path != "" {
		return nil, ErrPasskey
	}
	if u.Scheme != "https" && host != "localhost" {
		return nil, ErrPasskey
	}
	w, err := webauthn.New(&webauthn.Config{RPID: host, RPDisplayName: "Elemta Admin", RPOrigins: []string{origin}})
	if err != nil {
		return nil, ErrPasskey
	}
	return w, nil
}

func (r *record) credentials(host string) []webauthn.Credential {
	var out []webauthn.Credential
	for _, p := range r.Passkeys {
		if host == "" || p.Host == host {
			out = append(out, p.Credential)
		}
	}
	return out
}

// BeginAddPasskey starts registering a passkey for user at host. The caller
// has checked the user's password.
func (s *Store) BeginAddPasskey(user, host, origin string) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	w, err := RelyingParty(host, origin)
	if err != nil {
		return nil, nil, err
	}
	var existing []webauthn.Credential
	if err := s.view(func(f *file) error {
		if r := f.Users[user]; r != nil {
			if len(r.Passkeys) >= maxPasskeys {
				return fmt.Errorf("%w: that's the most passkeys one user can have", ErrInvalid)
			}
			existing = r.credentials("")
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(existing))
	for _, c := range existing {
		exclude = append(exclude, c.Descriptor())
	}
	required := true
	return w.BeginRegistration(webUser{name: user},
		webauthn.WithExclusions(exclude),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: &required, UserVerification: protocol.VerificationRequired,
		}))
}

// FinishAddPasskey checks the browser's answer and keeps the passkey.
func (s *Store) FinishAddPasskey(user, host, origin, name string, session webauthn.SessionData, response []byte) (PasskeyInfo, error) {
	var info PasskeyInfo
	name = strings.TrimSpace(name)
	if name == "" || len(name) > maxName {
		return info, fmt.Errorf("%w: give the passkey a name of up to %d characters", ErrInvalid, maxName)
	}
	w, err := RelyingParty(host, origin)
	if err != nil {
		return info, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(response))
	if err != nil {
		return info, ErrPasskey
	}
	err = s.update(func(f *file) error {
		r := f.user(user)
		if len(r.Passkeys) >= maxPasskeys {
			return fmt.Errorf("%w: that's the most passkeys one user can have", ErrInvalid)
		}
		credential, err := w.CreateCredential(webUser{name: user, credentials: r.credentials("")}, session, parsed)
		if err != nil {
			return ErrPasskey
		}
		// One authenticator, one passkey, across every user.
		for _, other := range f.Users {
			for _, p := range other.Passkeys {
				if bytes.Equal(p.Credential.ID, credential.ID) {
					return ErrPasskey
				}
			}
		}
		r.NextID++
		info = PasskeyInfo{ID: r.NextID, Name: name, Host: host, Created: time.Now().UTC()}
		r.Passkeys = append(r.Passkeys, passkey{PasskeyInfo: info, Credential: *credential})
		return nil
	})
	return info, err
}

// DeletePasskey removes one of a user's passkeys.
func (s *Store) DeletePasskey(user string, id int64) error {
	return s.update(func(f *file) error {
		r := f.Users[user]
		if r == nil {
			return ErrInvalid
		}
		n := len(r.Passkeys)
		r.Passkeys = slices.DeleteFunc(r.Passkeys, func(p passkey) bool { return p.ID == id })
		if len(r.Passkeys) == n {
			return ErrInvalid
		}
		return nil
	})
}

// BeginPasskeyLogin starts a sign-in with a passkey. With user empty, the
// passkey says whose it is, and must verify its holder (a fingerprint or
// PIN): it is then both factors. With user named, it is the second factor
// after their password.
func (s *Store) BeginPasskeyLogin(user, host, origin string) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	w, err := RelyingParty(host, origin)
	if err != nil {
		return nil, nil, err
	}
	if user == "" {
		return w.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	}
	var creds []webauthn.Credential
	if err := s.view(func(f *file) error {
		if r := f.Users[user]; r != nil {
			creds = r.credentials(host)
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}
	if len(creds) == 0 {
		return nil, nil, fmt.Errorf("%w: no passkey for this console's address; use a code", ErrPasskey)
	}
	return w.BeginLogin(webUser{name: user, credentials: creds}, webauthn.WithUserVerification(protocol.VerificationPreferred))
}

// FinishPasskeyLogin checks a passkey's signature and returns whose it is.
// With user named, it must be theirs.
func (s *Store) FinishPasskeyLogin(user, host, origin string, session webauthn.SessionData, response []byte) (string, error) {
	w, err := RelyingParty(host, origin)
	if err != nil {
		return "", err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(response))
	if err != nil {
		return "", ErrPasskey
	}
	who := ""
	err = s.update(func(f *file) error {
		var credential *webauthn.Credential
		var err error
		if user == "" {
			handler := func(rawID, handle []byte) (webauthn.User, error) {
				for name, r := range f.Users {
					if !bytes.Equal(handle, userHandle(name)) {
						continue
					}
					for _, p := range r.Passkeys {
						if p.Host == host && bytes.Equal(p.Credential.ID, rawID) {
							who = name
							return webUser{name: name, credentials: []webauthn.Credential{p.Credential}}, nil
						}
					}
				}
				return nil, ErrPasskey
			}
			_, credential, err = w.ValidatePasskeyLogin(handler, session, parsed)
		} else {
			r := f.Users[user]
			if r == nil {
				return ErrPasskey
			}
			who = user
			credential, err = w.ValidateLogin(webUser{name: user, credentials: r.credentials(host)}, session, parsed)
		}
		if err != nil || credential == nil || who == "" {
			return ErrPasskey
		}
		// A count going backwards means two devices hold one key, which a
		// real authenticator can't do. Synced passkeys stay at zero.
		if credential.Authenticator.CloneWarning {
			return ErrPasskey
		}
		r := f.Users[who]
		now := time.Now().UTC()
		for i := range r.Passkeys {
			if bytes.Equal(r.Passkeys[i].Credential.ID, credential.ID) {
				r.Passkeys[i].Credential = *credential
				r.Passkeys[i].LastUsed = &now
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return who, nil
}
