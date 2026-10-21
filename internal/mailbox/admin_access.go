package mailbox

// Administrator access to a mailbox: an administrator opens a user's
// mailbox in the webmail to help them or to investigate, without knowing or
// resetting their password.
//
// The dashboard asks the admin API for a token for one account
// (CreateAdminAccess), records that in the audit log, and hands the token
// to the webmail, which signs in with it. A token:
//
//   - is valid only on the internal IMAP listener the webmail uses, never on
//     the public IMAP or POP3 ports, so it can't be used from a mail app;
//   - is answered as kind "admin" by the security check, which the MTA
//     refuses for submission and the webmail refuses for DAV: an
//     administrator can read and manage the mail but not send as the user;
//   - expires after one hour, and only its SHA-256 is stored;
//   - skips the user's two-step verification, which is the point, so every
//     issue is in the audit log with the administrator's name.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

// adminTokenPrefix marks an administrator access token among passwords, so
// a login only looks one up when it could be one.
const adminTokenPrefix = "elemta-admin." // #nosec G101 -- public credential marker, not a credential

const adminAccessTTL = time.Hour

func adminTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateAdminAccess issues a token for account a on behalf of actor.
func (e *Engine) CreateAdminAccess(ctx context.Context, a Account, actor, client string) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token := adminTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	expires := time.Now().Add(adminAccessTTL).UTC().Truncate(time.Second)
	tx, err := e.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	defer func() { _ = tx.Rollback() }()
	// Expired tokens are removed as new ones are made; there are few.
	if _, err := tx.ExecContext(ctx, `DELETE FROM mailbox_admin_access WHERE expires < now()`); err != nil {
		return "", time.Time{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mailbox_admin_access(token_hash,account,actor,expires) VALUES($1,$2,$3,$4)`,
		adminTokenHash(token), a.ID, actor, expires)
	if err != nil {
		return "", time.Time{}, err
	}
	domain := ""
	if at := strings.LastIndexByte(a.Address, '@'); at >= 0 {
		domain = strings.ToLower(a.Address[at+1:])
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mailbox_audit(actor,source,client,action,target,domain,detail)
VALUES($1,'dashboard',$2,'mailbox-open',$3,$4,$5)`, actor, client, a.Address, domain, "access issued until "+expires.Format(time.RFC3339))
	if err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// adminAccess reports which account a token opens and for whom, if it is
// current.
func (e *Engine) adminAccess(ctx context.Context, token string) (account, actor string, expires time.Time, err error) {
	err = e.DB.QueryRowContext(ctx, `SELECT account, actor, expires FROM mailbox_admin_access WHERE token_hash=$1 AND expires > now()`, adminTokenHash(token)).Scan(&account, &actor, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", time.Time{}, ErrCredentials
	}
	return account, actor, expires, err
}

// adminLogin signs user in with an administrator access token. The token
// must belong to the account the directory has for user now, so it stops
// working if the account is deleted or the address passes to someone else.
func (s *Service) adminLogin(ctx context.Context, user, token string) (Account, string, time.Time, error) {
	if !strings.HasPrefix(token, adminTokenPrefix) {
		return Account{}, "", time.Time{}, ErrCredentials
	}
	id, actor, expires, err := s.engine.adminAccess(ctx, token)
	if err != nil {
		s.failLogin(strings.ToLower(user))
		return Account{}, "", time.Time{}, err
	}
	a, err := s.auth.Resolve(ctx, user)
	if err != nil {
		return Account{}, "", time.Time{}, err
	}
	if a.ID != id {
		return Account{}, "", time.Time{}, ErrCredentials
	}
	if err := s.applyPolicy(ctx, &a); err != nil {
		return Account{}, "", time.Time{}, err
	}
	if a.Policy != nil && !a.Policy.Allows(mailpolicy.Webmail) {
		return Account{}, "", time.Time{}, ErrProtocolDisabled
	}
	if err := s.engine.EnsureAccount(ctx, a); err != nil {
		return Account{}, "", time.Time{}, err
	}
	s.log.Info("mailbox: administrator access", "account", a.Address, "administrator", actor)
	return a, actor, expires, nil
}
