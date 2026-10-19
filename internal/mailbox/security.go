package mailbox

// Account security: two-step verification (TOTP, RFC 6238) for the webmail,
// and app passwords for mail apps.
//
// The mailbox service owns both, because it is the one place every login
// passes through: the webmail asks it over the internal API (security_api.go)
// whether a sign-in needs a code, and its own IMAP and POP3 listeners enforce
// the app-password requirement.
//
// App passwords are accepted wherever the account password is. When a user
// requires them, the account password stops working on the public IMAP and
// POP3 listeners, so a leaked password no longer reads mail from a client
// that skips the webmail's second step. The internal IMAP listener keeps
// accepting it, because the webmail signs in through it after the user has
// passed that second step.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 TOTP is defined over HMAC-SHA1 and authenticator apps implement only that
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/lib/pq"
)

const (
	totpPeriod      = 30
	totpDigits      = 6
	maxAppPasswords = 20
	recoveryCodes   = 10
)

var (
	// ErrAppPasswordRequired is a correct account password refused because
	// the user requires app passwords on this listener.
	ErrAppPasswordRequired = errors.New("app password required")
	// ErrBadCode is a wrong, reused or expired verification code.
	ErrBadCode    = errors.New("invalid verification code")
	ErrTOTPActive = errors.New("two-step verification is already enabled")
)

// SecurityState is what a user sees and changes in the webmail's settings.
type SecurityState struct {
	TOTP          bool          `json:"totp"`
	AppRequired   bool          `json:"app_required"`
	RecoveryLeft  int           `json:"recovery_left"`
	AppPasswords  []AppPassword `json:"app_passwords"`
	TOTPSetupOpen bool          `json:"totp_setup_open"`
}

// AppPassword describes one app password; the password itself is shown once,
// when it is created, and only its hash is stored.
type AppPassword struct {
	ID       int64      `json:"id"`
	Name     string     `json:"name"`
	Created  time.Time  `json:"created"`
	LastUsed *time.Time `json:"last_used,omitempty"`
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

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

// matchTOTP finds the time step a code belongs to, allowing one step of
// clock drift either way, and refuses steps at or before last so a code can
// be used only once.
func matchTOTP(secret []byte, code string, now time.Time, last int64) (int64, bool) {
	if len(code) != totpDigits {
		return 0, false
	}
	step := now.Unix() / totpPeriod
	for _, s := range []int64{step, step - 1, step + 1} {
		if s > last && hmac.Equal([]byte(totpCode(secret, s)), []byte(code)) {
			return s, true
		}
	}
	return 0, false
}

// normalizeCode strips what people type around codes and app passwords:
// spaces, dashes and case.
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

// secretHash stores app passwords and recovery codes. They are random with
// 75+ bits of entropy, so a fast hash is enough; a slow one is what protects
// passwords people choose.
func secretHash(s string) string {
	sum := sha256.Sum256([]byte(normalizeCode(s)))
	return hex.EncodeToString(sum[:])
}

// randomLetters returns n random lowercase letters, which read aloud and type
// on a phone more easily than mixed symbols.
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

func (e *Engine) securityRow(ctx context.Context, account string) (secret, pending string, last int64, required bool, codes []string, err error) {
	var sec, pend sql.NullString
	err = e.DB.QueryRowContext(ctx, `SELECT totp_secret,totp_pending,totp_last_step,app_passwords_required,recovery_codes FROM mailbox_security WHERE account=$1`, account).
		Scan(&sec, &pend, &last, &required, pq.Array(&codes))
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", 0, false, nil, nil
	}
	return sec.String, pend.String, last, required, codes, err
}

// SecurityState returns an account's settings.
func (e *Engine) SecurityState(ctx context.Context, account string) (SecurityState, error) {
	secret, pending, _, required, codes, err := e.securityRow(ctx, account)
	if err != nil {
		return SecurityState{}, err
	}
	st := SecurityState{TOTP: secret != "", AppRequired: required, RecoveryLeft: len(codes), TOTPSetupOpen: pending != "", AppPasswords: []AppPassword{}}
	rows, err := e.DB.QueryContext(ctx, `SELECT id,name,created,last_used FROM mailbox_app_passwords WHERE account=$1 ORDER BY created`, account)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var p AppPassword
		var used sql.NullTime
		if err := rows.Scan(&p.ID, &p.Name, &p.Created, &used); err != nil {
			return st, err
		}
		if used.Valid {
			p.LastUsed = &used.Time
		}
		st.AppPasswords = append(st.AppPasswords, p)
	}
	return st, rows.Err()
}

// AppPasswordsRequired reports whether the account password is refused on
// public mail listeners.
func (e *Engine) AppPasswordsRequired(ctx context.Context, account string) (bool, error) {
	_, _, _, required, _, err := e.securityRow(ctx, account)
	return required, err
}

// SetAppPasswordsRequired turns the requirement on or off.
func (e *Engine) SetAppPasswordsRequired(ctx context.Context, account string, required bool) error {
	_, err := e.DB.ExecContext(ctx, `INSERT INTO mailbox_security(account,app_passwords_required) VALUES($1,$2)
ON CONFLICT(account) DO UPDATE SET app_passwords_required=excluded.app_passwords_required`, account, required)
	return err
}

// CreateAppPassword returns a new app password, which is never stored.
func (e *Engine) CreateAppPassword(ctx context.Context, account, name string) (AppPassword, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return AppPassword{}, "", errors.New("app password name must be 1 to 64 characters")
	}
	letters, err := randomLetters(16)
	if err != nil {
		return AppPassword{}, "", err
	}
	password := groupBy4(letters)
	var p AppPassword
	err = e.tx(ctx, account, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM mailbox_app_passwords WHERE account=$1`, account).Scan(&n); err != nil {
			return err
		}
		if n >= maxAppPasswords {
			return fmt.Errorf("at most %d app passwords; delete one first", maxAppPasswords)
		}
		p.Name = name
		return tx.QueryRowContext(ctx, `INSERT INTO mailbox_app_passwords(account,name,hash) VALUES($1,$2,$3) RETURNING id,created`, account, name, secretHash(password)).Scan(&p.ID, &p.Created)
	})
	return p, password, err
}

// DeleteAppPassword revokes one app password.
func (e *Engine) DeleteAppPassword(ctx context.Context, account string, id int64) error {
	res, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_app_passwords WHERE account=$1 AND id=$2`, account, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// appPasswordAccount finds the account an app password belongs to, if the
// address matches, and records its use.
func (e *Engine) appPasswordAccount(ctx context.Context, address, password string) (string, bool, error) {
	if len(password) > 64 {
		return "", false, nil
	}
	var id int64
	var account string
	err := e.DB.QueryRowContext(ctx, `SELECT p.id,a.id FROM mailbox_app_passwords p JOIN mailbox_accounts a ON a.id=p.account
WHERE p.hash=$1 AND lower(a.address)=$2`, secretHash(password), strings.ToLower(address)).Scan(&id, &account)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	_, _ = e.DB.ExecContext(ctx, `UPDATE mailbox_app_passwords SET last_used=now() WHERE id=$1 AND (last_used IS NULL OR last_used<now()-interval '1 minute')`, id)
	return account, true, nil
}

// BeginTOTP creates a pending secret and returns it with its otpauth URI.
// It takes effect only once ConfirmTOTP proves the user's app has it.
func (e *Engine) BeginTOTP(ctx context.Context, account, address, issuer string) (secret, uri string, err error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	secret = b32.EncodeToString(raw)
	sealed, err := e.sealTOTP(account, "pending", secret)
	if err != nil {
		return "", "", err
	}
	err = e.tx(ctx, account, func(tx *sql.Tx) error {
		var active bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mailbox_security WHERE account=$1 AND totp_secret IS NOT NULL)`, account).Scan(&active); err != nil {
			return err
		}
		if active {
			return ErrTOTPActive
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO mailbox_security(account,totp_pending,totp_pending_at) VALUES($1,$2,now())
ON CONFLICT(account) DO UPDATE SET totp_pending=excluded.totp_pending,totp_pending_at=excluded.totp_pending_at`, account, sealed)
		return err
	})
	if err != nil {
		return "", "", err
	}
	label := url.PathEscape(issuer + ":" + address)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return secret, "otpauth://totp/" + label + "?" + q.Encode(), nil
}

// ConfirmTOTP turns two-step verification on once a code from the pending
// secret checks out, and returns new recovery codes, shown once.
func (e *Engine) ConfirmTOTP(ctx context.Context, account, code string, now time.Time) ([]string, error) {
	plain := make([]string, recoveryCodes)
	hashed := make([]string, recoveryCodes)
	for i := range plain {
		letters, err := randomLetters(10)
		if err != nil {
			return nil, err
		}
		plain[i] = letters[:5] + "-" + letters[5:]
		hashed[i] = secretHash(plain[i])
	}
	err := e.tx(ctx, account, func(tx *sql.Tx) error {
		var pending sql.NullString
		var pendingAt sql.NullTime
		var active bool
		if err := tx.QueryRowContext(ctx, `SELECT totp_pending,totp_pending_at,totp_secret IS NOT NULL FROM mailbox_security WHERE account=$1 FOR UPDATE`, account).Scan(&pending, &pendingAt, &active); err != nil || !pending.Valid || !pendingAt.Valid || now.Sub(pendingAt.Time) > 5*time.Minute {
			return ErrBadCode
		}
		if active {
			return ErrTOTPActive
		}
		plain, err := e.openTOTP(account, "pending", pending.String)
		if err != nil {
			return err
		}
		raw, err := b32.DecodeString(plain)
		if err != nil {
			return ErrBadCode
		}
		step, ok := matchTOTP(raw, normalizeCode(code), now, 0)
		if !ok {
			return ErrBadCode
		}
		sealed, err := e.sealTOTP(account, "active", plain)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE mailbox_security SET totp_secret=$4,totp_pending=NULL,totp_pending_at=NULL,totp_last_step=$2,recovery_codes=$3 WHERE account=$1`, account, step, pq.Array(hashed), sealed)
		return err
	})
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// VerifySecondFactor checks a code from the user's app, or one of their
// recovery codes, which is then used up. Each TOTP code works once.
func (e *Engine) VerifySecondFactor(ctx context.Context, account, code string, now time.Time) (recovery bool, err error) {
	code = normalizeCode(code)
	err = e.tx(ctx, account, func(tx *sql.Tx) error {
		var secret sql.NullString
		var last int64
		var codes []string
		if err := tx.QueryRowContext(ctx, `SELECT totp_secret,totp_last_step,recovery_codes FROM mailbox_security WHERE account=$1 FOR UPDATE`, account).
			Scan(&secret, &last, pq.Array(&codes)); err != nil || !secret.Valid {
			return ErrBadCode
		}
		plain, err := e.openTOTP(account, "active", secret.String)
		if err != nil {
			return err
		}
		raw, err := b32.DecodeString(plain)
		if err != nil {
			return ErrBadCode
		}
		if step, ok := matchTOTP(raw, code, now, last); ok {
			_, err := tx.ExecContext(ctx, `UPDATE mailbox_security SET totp_last_step=$2 WHERE account=$1`, account, step)
			return err
		}
		h := secretHash(code)
		for i, c := range codes {
			if hmac.Equal([]byte(c), []byte(h)) {
				recovery = true
				_, err := tx.ExecContext(ctx, `UPDATE mailbox_security SET recovery_codes=$2 WHERE account=$1`, account, pq.Array(append(codes[:i:i], codes[i+1:]...)))
				return err
			}
		}
		return ErrBadCode
	})
	return recovery, err
}

// DisableTOTP turns two-step verification off. The caller has checked a
// current code.
func (e *Engine) DisableTOTP(ctx context.Context, account string) error {
	_, err := e.DB.ExecContext(ctx, `UPDATE mailbox_security SET totp_secret=NULL,totp_pending=NULL,totp_pending_at=NULL,totp_last_step=0,recovery_codes='{}' WHERE account=$1`, account)
	return err
}
