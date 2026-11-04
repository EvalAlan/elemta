package adminmfa

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

func TestAuthenticatorApp(t *testing.T) {
	path := PathFor(filepath.Join(t.TempDir(), "users"))
	s := Open(path)
	now := time.Now()

	st, err := s.Status("root")
	if err != nil || st.On() || len(st.Methods()) != 0 {
		t.Fatalf("new user: %+v %v", st, err)
	}
	secret, uri, err := s.BeginTOTP("root", "Elemta Admin (mx.example.com)")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "otpauth://totp/Elemta%20Admin%20%28mx.example.com%29:root?") || !strings.Contains(uri, "secret="+secret) {
		t.Errorf("uri = %s", uri)
	}
	// Pending isn't on: signing in still needs only the password.
	if st, _ := s.Status("root"); st.On() {
		t.Fatal("a pending authenticator counts as on")
	}
	key, _ := b32.DecodeString(secret)
	wrong := "000000"
	if totpCode(key, now.Unix()/30) == wrong || totpCode(key, now.Unix()/30-1) == wrong || totpCode(key, now.Unix()/30+1) == wrong {
		wrong = "111111"
	}
	if _, err := s.ConfirmTOTP("root", wrong, now); !errors.Is(err, ErrWrongCode) {
		t.Fatalf("wrong confirm code: %v", err)
	}
	codes, err := s.ConfirmTOTP("root", totpCode(key, now.Unix()/30), now)
	if err != nil || len(codes) != 10 || len(codes[0]) != 19 {
		t.Fatalf("confirm = %q %v", codes, err)
	}
	if st, _ := s.Status("root"); !st.TOTP || st.RecoveryLeft != 10 || strings.Join(st.Methods(), ",") != "totp" {
		t.Fatalf("after confirming: %+v", st)
	}
	if _, _, err := s.BeginTOTP("root", "x"); !errors.Is(err, ErrActive) {
		t.Errorf("second setup: %v", err)
	}

	// The confirming code can't be used again, the next one can, once.
	if _, err := s.VerifyCode("root", totpCode(key, now.Unix()/30), now); !errors.Is(err, ErrWrongCode) {
		t.Errorf("replayed code: %v", err)
	}
	later := now.Add(30 * time.Second)
	if recovery, err := s.VerifyCode("root", totpCode(key, later.Unix()/30), later); err != nil || recovery {
		t.Errorf("next code: %v %v", recovery, err)
	}
	if _, err := s.VerifyCode("root", totpCode(key, later.Unix()/30), later); !errors.Is(err, ErrWrongCode) {
		t.Errorf("replayed next code: %v", err)
	}
	// A recovery code works once, typed however.
	typed := strings.ToUpper(strings.ReplaceAll(codes[3], "-", " "))
	if recovery, err := s.VerifyCode("root", typed, later); err != nil || !recovery {
		t.Errorf("recovery code: %v %v", recovery, err)
	}
	if _, err := s.VerifyCode("root", codes[3], later); !errors.Is(err, ErrWrongCode) {
		t.Errorf("reused recovery code: %v", err)
	}
	if st, _ := s.Status("root"); st.RecoveryLeft != 9 {
		t.Errorf("recovery left = %d", st.RecoveryLeft)
	}
	fresh, err := s.NewRecoveryCodes("root")
	if err != nil || len(fresh) != 10 {
		t.Fatal(err)
	}
	if _, err := s.VerifyCode("root", codes[4], later); !errors.Is(err, ErrWrongCode) {
		t.Error("old recovery codes survived replacement")
	}
	for _, code := range []string{"", "12345", "1234567", "zzzz-zzzz-zzzz-zzzz"} {
		if _, err := s.VerifyCode("root", code, later); !errors.Is(err, ErrWrongCode) {
			t.Errorf("code %q: %v", code, err)
		}
	}
	if _, err := s.VerifyCode("nobody", "123456", later); !errors.Is(err, ErrWrongCode) {
		t.Errorf("user without an app: %v", err)
	}

	// Kept with the console only, and nothing else in the directory.
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v %v", info.Mode(), err)
	}
	if strings.Contains(string(mustRead(t, path)), fresh[0]) {
		t.Error("recovery codes are stored as they were shown")
	}
	users, _ := s.Users()
	if !users["root"] || len(users) != 1 {
		t.Errorf("users = %v", users)
	}

	if err := s.DisableTOTP("root"); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Status("root"); st.On() || st.RecoveryLeft != 0 {
		t.Errorf("after turning off: %+v", st)
	}
}

func TestPendingAuthenticatorExpires(t *testing.T) {
	s := Open(filepath.Join(t.TempDir(), "users.2fa"))
	secret, _, err := s.BeginTOTP("root", "x")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := b32.DecodeString(secret)
	late := time.Now().Add(time.Hour)
	if _, err := s.ConfirmTOTP("root", totpCode(key, late.Unix()/30), late); !errors.Is(err, ErrNoPending) {
		t.Fatalf("stale confirm: %v", err)
	}
	if _, err := s.ConfirmTOTP("other", "123456", time.Now()); !errors.Is(err, ErrNoPending) {
		t.Fatalf("confirm without setup: %v", err)
	}
}

func TestResetAndConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.2fa")
	s := Open(path)
	var wg sync.WaitGroup
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Two stores on one file, as the console and the CLI are.
			other := Open(path)
			secret, _, err := other.BeginTOTP(name, "x")
			if err != nil {
				t.Error(err)
				return
			}
			key, _ := b32.DecodeString(secret)
			now := time.Now()
			if _, err := s.ConfirmTOTP(name, totpCode(key, now.Unix()/30), now); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	users, err := s.Users()
	if err != nil || len(users) != 8 {
		t.Fatalf("users after concurrent setup = %v %v", users, err)
	}
	if err := s.Reset("c"); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Status("c"); st.On() {
		t.Error("reset left a second factor")
	}
	if users, _ := s.Users(); len(users) != 7 {
		t.Errorf("reset removed others: %v", users)
	}
}

func TestRelyingParty(t *testing.T) {
	for _, c := range []struct {
		host, origin string
		ok           bool
	}{
		{"admin.example.com", "https://admin.example.com", true},
		{"admin.example.com", "https://admin.example.com:8443", true},
		{"localhost", "http://localhost:8025", true},
		{"admin.example.com", "http://admin.example.com", false},
		{"admin.example.com", "https://evil.example.com", false},
		{"", "https://", false},
		{"admin.example.com", "https://admin.example.com/path", false},
	} {
		if _, err := RelyingParty(c.host, c.origin); (err == nil) != c.ok {
			t.Errorf("%s %s: %v", c.host, c.origin, err)
		}
	}
	s := Open(filepath.Join(t.TempDir(), "users.2fa"))
	creation, session, err := s.BeginAddPasskey("root", "localhost", "http://localhost:8025")
	if err != nil || session == nil || creation.Response.RelyingParty.ID != "localhost" {
		t.Fatalf("begin add: %v", err)
	}
	if id, ok := creation.Response.User.ID.(protocol.URLEncodedBase64); !ok || string(id) != string(userHandle("root")) {
		t.Error("user handle isn't the hashed name")
	}
	if _, _, err := s.BeginPasskeyLogin("root", "localhost", "http://localhost:8025"); !errors.Is(err, ErrPasskey) {
		t.Errorf("second-factor passkey sign-in without passkeys: %v", err)
	}
	if _, _, err := s.BeginPasskeyLogin("", "localhost", "http://localhost:8025"); err != nil {
		t.Errorf("passkey sign-in: %v", err)
	}
	if _, err := s.FinishAddPasskey("root", "localhost", "http://localhost:8025", "", *session, []byte("{}")); !errors.Is(err, ErrInvalid) {
		t.Errorf("nameless passkey: %v", err)
	}
	if _, err := s.FinishAddPasskey("root", "localhost", "http://localhost:8025", "Laptop", *session, []byte("{}")); !errors.Is(err, ErrPasskey) {
		t.Errorf("garbage response: %v", err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- test file
	if err != nil {
		t.Fatal(err)
	}
	return b
}
