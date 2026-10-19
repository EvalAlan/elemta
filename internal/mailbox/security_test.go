package mailbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1, truncated to the six digits apps show.
func TestTOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		if got := totpCode(secret, unix/totpPeriod); got != want {
			t.Errorf("TOTP at %d = %s, want %s", unix, got, want)
		}
	}
	now := time.Unix(1111111109, 0)
	step, ok := matchTOTP(secret, "081804", now, 0)
	if !ok {
		t.Fatal("current code refused")
	}
	if _, ok := matchTOTP(secret, "081804", now, step); ok {
		t.Fatal("code accepted twice")
	}
	if _, ok := matchTOTP(secret, totpCode(secret, step+1), now, 0); !ok {
		t.Error("one step of clock drift refused")
	}
	if _, ok := matchTOTP(secret, totpCode(secret, step+2), now, 0); ok {
		t.Error("code two steps ahead accepted")
	}
}

func TestAppPasswordsByListener(t *testing.T) {
	e, a := testEngine(t)
	s, _, _ := startTestService(t, e, a)
	ctx := context.Background()
	if _, err := s.login(ctx, a.Address, "testpass", true, ""); err != nil {
		t.Fatalf("account password before any requirement: %v", err)
	}
	_, password, err := e.CreateAppPassword(ctx, a.ID, "Phone")
	if err != nil {
		t.Fatal(err)
	}
	// Apps differ in how they let people paste: case and dashes don't matter.
	for _, typed := range []string{password, strings.ToUpper(strings.ReplaceAll(password, "-", " "))} {
		if got, err := s.login(ctx, a.Address, typed, true, ""); err != nil || got.ID != a.ID {
			t.Fatalf("app password %q: %v", typed, err)
		}
	}
	if _, err := s.login(ctx, "someone-else@example.com", password, true, ""); err == nil {
		t.Fatal("app password accepted for another address")
	}
	if err := e.SetAppPasswordsRequired(ctx, a.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.login(ctx, a.Address, "testpass", true, ""); !errors.Is(err, ErrCredentials) {
		t.Fatalf("account password on a public listener with the requirement: %v", err)
	}
	if _, err := s.login(ctx, a.Address, "testpass", false, ""); err != nil {
		t.Fatalf("account password on the internal listener: %v", err)
	}
	if _, err := s.login(ctx, a.Address, password, true, ""); err != nil {
		t.Fatalf("app password with the requirement: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	watchCtx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	ticks := make(chan time.Time)
	active := &imapSession{service: s, ctx: watchCtx, cancel: stopWatch, conn: serverConn,
		account: a, user: a.Address, password: password, public: true, recheck: ticks}
	go active.watchCredentials()
	st, err := e.SecurityState(ctx, a.ID)
	if err != nil || len(st.AppPasswords) != 1 || st.AppPasswords[0].LastUsed == nil || !st.AppRequired {
		t.Fatalf("state = %+v, %v", st, err)
	}
	if err := e.DeleteAppPassword(ctx, a.ID, st.AppPasswords[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.login(ctx, a.Address, password, true, ""); err == nil {
		t.Fatal("deleted app password still works")
	}
	ticks <- time.Now()
	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := clientConn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("established IMAP connection remained open after revocation: %v", err)
	}
}

func TestSecondFactor(t *testing.T) {
	t.Setenv("ELEMTA_MAILBOX_TOTP_KEYS", "v1:"+base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901")))
	e, a := testEngine(t)
	ctx := context.Background()
	now := time.Now()
	secret, uri, err := e.BeginTOTP(ctx, a.ID, a.Address, "Elemta Mail")
	if err != nil || !strings.HasPrefix(uri, "otpauth://totp/") || !strings.Contains(uri, "secret="+secret) {
		t.Fatalf("begin = %s %s %v", secret, uri, err)
	}
	var stored string
	if err := e.DB.QueryRow(`SELECT totp_pending FROM mailbox_security WHERE account=$1`, a.ID).Scan(&stored); err != nil || strings.Contains(stored, secret) || !strings.HasPrefix(stored, "enc:v1:") {
		t.Fatalf("pending seed was stored in plaintext: %v", err)
	}
	if _, err := e.VerifySecondFactor(ctx, a.ID, "000000", now); !errors.Is(err, ErrBadCode) {
		t.Fatal("pending secret is already in force")
	}
	raw, _ := b32.DecodeString(secret)
	step := now.Unix() / totpPeriod
	if _, err := e.ConfirmTOTP(ctx, a.ID, "123", now); !errors.Is(err, ErrBadCode) {
		t.Fatal("bad confirmation code accepted")
	}
	codes, err := e.ConfirmTOTP(ctx, a.ID, totpCode(raw, step), now)
	if err != nil || len(codes) != recoveryCodes {
		t.Fatalf("confirm = %v %v", codes, err)
	}
	if err := e.DB.QueryRow(`SELECT totp_secret FROM mailbox_security WHERE account=$1`, a.ID).Scan(&stored); err != nil || strings.Contains(stored, secret) || !strings.HasPrefix(stored, "enc:v1:") {
		t.Fatalf("active seed was stored in plaintext: %v", err)
	}
	if _, _, err := e.BeginTOTP(ctx, a.ID, a.Address, "Elemta Mail"); !errors.Is(err, ErrTOTPActive) {
		t.Fatalf("active factor could be replaced: %v", err)
	}
	// The confirming code is spent; the next step's code works once.
	if _, err := e.VerifySecondFactor(ctx, a.ID, totpCode(raw, step), now); !errors.Is(err, ErrBadCode) {
		t.Fatal("confirmation code reused")
	}
	if rec, err := e.VerifySecondFactor(ctx, a.ID, totpCode(raw, step+1), now); err != nil || rec {
		t.Fatalf("next code = %v %v", rec, err)
	}
	if _, err := e.VerifySecondFactor(ctx, a.ID, totpCode(raw, step+1), now); !errors.Is(err, ErrBadCode) {
		t.Fatal("TOTP code reused")
	}
	if rec, err := e.VerifySecondFactor(ctx, a.ID, strings.ToUpper(codes[3]), now); err != nil || !rec {
		t.Fatalf("recovery code = %v %v", rec, err)
	}
	if _, err := e.VerifySecondFactor(ctx, a.ID, codes[3], now); !errors.Is(err, ErrBadCode) {
		t.Fatal("recovery code reused")
	}
	if st, _ := e.SecurityState(ctx, a.ID); !st.TOTP || st.RecoveryLeft != recoveryCodes-1 {
		t.Fatalf("state = %+v", st)
	}
	if err := e.DisableTOTP(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.SecurityState(ctx, a.ID); st.TOTP || st.RecoveryLeft != 0 {
		t.Fatalf("state after disable = %+v", st)
	}
	expired, _, err := e.BeginTOTP(ctx, a.ID, a.Address, "Elemta Mail")
	if err != nil {
		t.Fatal(err)
	}
	expiredRaw, _ := b32.DecodeString(expired)
	later := time.Now().Add(6 * time.Minute)
	if _, err := e.ConfirmTOTP(ctx, a.ID, totpCode(expiredRaw, later.Unix()/totpPeriod), later); !errors.Is(err, ErrBadCode) {
		t.Fatalf("expired enrollment was accepted: %v", err)
	}
}

func TestTOTPPlaintextMigrationRequiresKey(t *testing.T) {
	key := "v1:" + base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	t.Setenv("ELEMTA_MAILBOX_TOTP_KEYS", key)
	e, a := testEngine(t)
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	if _, err := e.DB.Exec(`INSERT INTO mailbox_security(account,totp_secret) VALUES($1,$2)`, a.ID, secret); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ELEMTA_MAILBOX_TOTP_KEYS", "")
	if _, err := NewEngine(context.Background(), e.DB, e.Bodies, Config{}.WithDefaults()); err == nil {
		t.Fatal("started with plaintext TOTP state and no external key")
	}
	t.Setenv("ELEMTA_MAILBOX_TOTP_KEYS", key)
	restarted, err := NewEngine(context.Background(), e.DB, e.Bodies, Config{}.WithDefaults())
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := e.DB.QueryRow(`SELECT totp_secret FROM mailbox_security WHERE account=$1`, a.ID).Scan(&stored); err != nil || !strings.HasPrefix(stored, "enc:v1:") || strings.Contains(stored, secret) {
		t.Fatalf("migration left plaintext seed: %v", err)
	}
	now := time.Now()
	if _, err := restarted.VerifySecondFactor(context.Background(), a.ID, totpCode([]byte("12345678901234567890"), now.Unix()/totpPeriod), now); err != nil {
		t.Fatalf("migrated seed cannot verify: %v", err)
	}
}

func TestSecurityAPI(t *testing.T) {
	e, a := testEngine(t)
	s, _, _ := startTestService(t, e, a)
	call := func(remote, method, path, user, password, body string) (int, map[string]any) {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = remote
		if user != "" {
			r.SetBasicAuth(user, password)
		}
		w := httptest.NewRecorder()
		s.http.Handler.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	const local = "127.0.0.1:5000"
	if code, _ := call("192.0.2.7:5000", "GET", "/v1/security", a.Address, "testpass", ""); code != http.StatusForbidden {
		t.Fatalf("outside network = %d", code)
	}
	if code, _ := call(local, "GET", "/v1/security", a.Address, "wrong", ""); code != http.StatusUnauthorized {
		t.Fatalf("wrong password = %d", code)
	}
	code, out := call(local, "POST", "/v1/security/app-passwords", a.Address, "testpass", `{"name":"Laptop"}`)
	if code != http.StatusOK {
		t.Fatalf("create = %d", code)
	}
	app, _ := out["password"].(string)
	// An app password may sign in, but never change the settings it is
	// protected by.
	if code, _ := call(local, "POST", "/v1/security/app-required", a.Address, app, `{"required":false}`); code != http.StatusUnauthorized {
		t.Fatalf("settings changed with an app password: %d", code)
	}
	code, out = call(local, "POST", "/v1/security/check", a.Address, app, "")
	if code != http.StatusOK || out["kind"] != "app" {
		t.Fatalf("check with app password = %d %v", code, out)
	}
	code, out = call(local, "POST", "/v1/security/check", a.Address, "testpass", "")
	if code != http.StatusOK || out["kind"] != "password" || out["totp"] != false {
		t.Fatalf("check = %d %v", code, out)
	}
	if code, _ := call(local, "POST", "/v1/security/verify", a.Address, "testpass", `{"code":"123456"}`); code != http.StatusUnprocessableEntity {
		t.Fatalf("verify without TOTP = %d", code)
	}
}
