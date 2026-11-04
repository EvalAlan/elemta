package mailbox

// Passkeys: signing in to the webmail with a device instead of a password.
//
// Everything past the sign-in page needs a credential to present, because the
// webmail reaches the mailbox, ManageSieve and submission as the user. It keeps
// the password for that (internal/webmail/session.go), and a passkey sign-in
// has no password. So this service, which holds the passkeys and checks them,
// issues a session token that stands in for one:
//
//   - it works only where the webmail connects: never on a public IMAP or POP3
//     port, never for DAV, and at the MTA only on the webmail's own submission
//     port, so it can't be used from a mail app;
//   - it lapses after sessionTokenIdle unused and sessionTokenMax in all, and
//     only its SHA-256 is stored;
//   - signing out, removing the passkey or an administrator's reset ends it.
//
// A passkey counts as both factors, because the device requires its PIN or
// biometric: user verification is demanded here, not left to the device.
//
// Adding one takes the account password, even in a session already signed in.
// Otherwise a stolen session could leave itself a permanent way back in.
//
// A passkey belongs to the host name it was made on, by the design of WebAuthn:
// that is what stops a look-alike site using it. The webmail says which host a
// request came through. It can't lie to much effect, because the browser binds
// each signature to the real one.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lib/pq"
)

// sessionTokenPrefix marks a session token among passwords, so a login only
// looks one up when it could be one.
const sessionTokenPrefix = "elemta-session." // #nosec G101 -- public credential marker, not a credential

const (
	sessionTokenIdle = 12 * time.Hour
	sessionTokenMax  = 7 * 24 * time.Hour
	passkeyChallenge = 5 * time.Minute
	maxPasskeys      = 20
	maxPasskeyName   = 64
)

var errPasskey = &requestError{"the passkey wasn't accepted"}

// PasskeyInfo is a passkey as its owner sees it.
type PasskeyInfo struct {
	ID       int64      `json:"id"`
	Name     string     `json:"name"`
	Host     string     `json:"host"`
	Created  time.Time  `json:"created"`
	LastUsed *time.Time `json:"last_used,omitempty"`
}

// passkeyUser presents an account to the WebAuthn library. The user handle is a
// hash because the account's ID can be longer than the 64 bytes allowed, and
// because a handle shouldn't say anything about who it is.
type passkeyUser struct {
	account     Account
	credentials []webauthn.Credential
}

func passkeyHandle(account string) []byte {
	sum := sha256.Sum256([]byte("passkey-user:" + account))
	return sum[:]
}

func (u passkeyUser) WebAuthnID() []byte                         { return passkeyHandle(u.account.ID) }
func (u passkeyUser) WebAuthnName() string                       { return u.account.Address }
func (u passkeyUser) WebAuthnDisplayName() string                { return u.account.Address }
func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// relyingParty is the site a passkey belongs to. Each request names its own,
// since one server answers for several domains.
func relyingParty(host, origin string) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() != host || host == "" || u.Path != "" {
		return nil, errPasskey
	}
	if u.Scheme != "https" && host != "localhost" {
		return nil, errPasskey
	}
	w, err := webauthn.New(&webauthn.Config{RPID: host, RPDisplayName: "Elemta Mail", RPOrigins: []string{origin}})
	if err != nil {
		return nil, errPasskey
	}
	return w, nil
}

func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// saveChallenge keeps a ceremony's state in the database, because the second
// half may reach another replica.
func (e *Engine) saveChallenge(ctx context.Context, account string, session *webauthn.SessionData) (string, error) {
	id, err := randomToken()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	if _, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_passkey_challenges WHERE expires < now()`); err != nil {
		return "", err
	}
	_, err = e.DB.ExecContext(ctx, `INSERT INTO mailbox_passkey_challenges(id,account,session,expires) VALUES($1,$2,$3,$4)`,
		id, account, data, time.Now().Add(passkeyChallenge))
	return id, err
}

// takeChallenge removes a challenge as it reads it, so each is good only once.
func (e *Engine) takeChallenge(ctx context.Context, id, account string) (webauthn.SessionData, error) {
	var session webauthn.SessionData
	var data []byte
	err := e.DB.QueryRowContext(ctx, `DELETE FROM mailbox_passkey_challenges WHERE id=$1 AND account=$2 AND expires>now() RETURNING session`, id, account).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return session, errPasskey
	}
	if err != nil {
		return session, err
	}
	return session, json.Unmarshal(data, &session)
}

func (e *Engine) passkeyCredentials(ctx context.Context, account string) ([]webauthn.Credential, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT credential FROM mailbox_passkeys WHERE account=$1 ORDER BY id`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []webauthn.Credential
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var c webauthn.Credential
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// BeginPasskeyRegistration starts adding a passkey. The caller has already
// checked the account password.
func (s *Service) beginPasskeyRegistration(ctx context.Context, a Account, host, origin string) (string, *protocol.CredentialCreation, error) {
	w, err := relyingParty(host, origin)
	if err != nil {
		return "", nil, err
	}
	existing, err := s.engine.passkeyCredentials(ctx, a.ID)
	if err != nil {
		return "", nil, err
	}
	if len(existing) >= maxPasskeys {
		return "", nil, &requestError{"that's the most passkeys one account can have"}
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(existing))
	for _, c := range existing {
		exclude = append(exclude, c.Descriptor())
	}
	required := true
	creation, session, err := w.BeginRegistration(passkeyUser{account: a},
		webauthn.WithExclusions(exclude),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: &required, UserVerification: protocol.VerificationRequired,
		}))
	if err != nil {
		return "", nil, err
	}
	id, err := s.engine.saveChallenge(ctx, a.ID, session)
	return id, creation, err
}

// finishPasskeyRegistration stores a new passkey.
func (s *Service) finishPasskeyRegistration(ctx context.Context, a Account, host, origin, challenge, name string, response []byte) (PasskeyInfo, error) {
	var info PasskeyInfo
	name = strings.TrimSpace(name)
	if name == "" || len(name) > maxPasskeyName {
		return info, &requestError{"give the passkey a name"}
	}
	w, err := relyingParty(host, origin)
	if err != nil {
		return info, err
	}
	session, err := s.engine.takeChallenge(ctx, challenge, a.ID)
	if err != nil {
		return info, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(response))
	if err != nil {
		return info, errPasskey
	}
	existing, err := s.engine.passkeyCredentials(ctx, a.ID)
	if err != nil {
		return info, err
	}
	credential, err := w.CreateCredential(passkeyUser{account: a, credentials: existing}, session, parsed)
	if err != nil {
		return info, errPasskey
	}
	data, err := json.Marshal(credential)
	if err != nil {
		return info, err
	}
	err = s.engine.DB.QueryRowContext(ctx, `INSERT INTO mailbox_passkeys(account,credential_id,credential,name,host) VALUES($1,$2,$3,$4,$5) RETURNING id,created`,
		a.ID, credential.ID, data, name, host).Scan(&info.ID, &info.Created)
	var pe *pq.Error
	if errors.As(err, &pe) && pe.Code == "23505" {
		return info, errPasskey
	}
	if err != nil {
		return info, err
	}
	info.Name, info.Host = name, host
	_, err = s.engine.Audit(ctx, mailpolicy.AuditEntry{Actor: a.Address, Source: "webmail", Action: "passkey-add", Target: a.Address, Detail: name})
	return info, err
}

// beginPasskeyLogin starts a sign-in. Nobody is named yet: the passkey says who
// it belongs to, so the page needn't ask, and asking would reveal who has one.
func (s *Service) beginPasskeyLogin(ctx context.Context, host, origin string) (string, *protocol.CredentialAssertion, error) {
	w, err := relyingParty(host, origin)
	if err != nil {
		return "", nil, err
	}
	assertion, session, err := w.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return "", nil, err
	}
	id, err := s.engine.saveChallenge(ctx, "", session)
	return id, assertion, err
}

// finishPasskeyLogin checks a signature and issues a session token.
func (s *Service) finishPasskeyLogin(ctx context.Context, host, origin, challenge string, response []byte) (string, string, error) {
	w, err := relyingParty(host, origin)
	if err != nil {
		return "", "", err
	}
	session, err := s.engine.takeChallenge(ctx, challenge, "")
	if err != nil {
		return "", "", err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(response))
	if err != nil {
		return "", "", errPasskey
	}
	var key int64
	var account Account
	var data []byte
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		err := s.engine.DB.QueryRowContext(ctx, `SELECT p.id,p.account,a.address,p.credential FROM mailbox_passkeys p JOIN mailbox_accounts a ON a.id=p.account WHERE p.credential_id=$1 AND p.host=$2`,
			rawID, host).Scan(&key, &account.ID, &account.Address, &data)
		if err != nil {
			return nil, errPasskey
		}
		var c webauthn.Credential
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, err
		}
		if !bytes.Equal(userHandle, passkeyHandle(account.ID)) {
			return nil, errPasskey
		}
		return passkeyUser{account: account, credentials: []webauthn.Credential{c}}, nil
	}
	_, credential, err := w.ValidatePasskeyLogin(handler, session, parsed)
	if err != nil {
		return "", "", errPasskey
	}
	// A count going backwards means two devices hold one key, which a real
	// authenticator can't do. Synced passkeys keep it at zero, which is fine.
	if credential.Authenticator.CloneWarning {
		s.log.Warn("mailbox: passkey may be cloned; refused", "account", account.Address)
		return "", "", errPasskey
	}
	a, err := s.passkeyAccount(ctx, account.ID, account.Address)
	if err != nil {
		return "", "", err
	}
	updated, err := json.Marshal(credential)
	if err != nil {
		return "", "", err
	}
	if _, err := s.engine.DB.ExecContext(ctx, `UPDATE mailbox_passkeys SET credential=$2,last_used=now() WHERE id=$1`, key, updated); err != nil {
		return "", "", err
	}
	token, err := s.engine.issueSessionToken(ctx, a.ID, key)
	if err != nil {
		return "", "", err
	}
	s.log.Info("mailbox: passkey sign-in", "account", a.Address)
	return a.Address, token, nil
}

// passkeyAccount is the account as the directory has it now, so that deleting or
// suspending someone ends their passkeys too.
func (s *Service) passkeyAccount(ctx context.Context, id, address string) (Account, error) {
	a, err := s.auth.Resolve(ctx, address)
	if err != nil {
		return Account{}, err
	}
	if a.ID != id || a.Suspended {
		return Account{}, ErrCredentials
	}
	if err := s.applyPolicy(ctx, &a); err != nil {
		return Account{}, err
	}
	if a.Policy != nil && !a.Policy.Allows(mailpolicy.Webmail) {
		return Account{}, ErrProtocolDisabled
	}
	return a, s.engine.EnsureAccount(ctx, a)
}

func (e *Engine) issueSessionToken(ctx context.Context, account string, passkey int64) (string, error) {
	raw, err := randomToken()
	if err != nil {
		return "", err
	}
	token := sessionTokenPrefix + raw
	if _, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_session_tokens WHERE expires<now() OR absolute_expires<now()`); err != nil {
		return "", err
	}
	now := time.Now()
	_, err = e.DB.ExecContext(ctx, `INSERT INTO mailbox_session_tokens(token_hash,account,passkey,expires,absolute_expires) VALUES($1,$2,$3,$4,$5)`,
		adminTokenHash(token), account, passkey, now.Add(sessionTokenIdle), now.Add(sessionTokenMax))
	return token, err
}

// sessionLogin signs user in with a session token, on the internal listener
// only. The token has to belong to the account the directory has for user now.
func (s *Service) sessionLogin(ctx context.Context, user, token string) (Account, error) {
	var id string
	var expires, absolute time.Time
	err := s.engine.DB.QueryRowContext(ctx, `SELECT account,expires,absolute_expires FROM mailbox_session_tokens WHERE token_hash=$1 AND expires>now() AND absolute_expires>now()`,
		adminTokenHash(token)).Scan(&id, &expires, &absolute)
	if errors.Is(err, sql.ErrNoRows) {
		s.failLogin(strings.ToLower(user))
		return Account{}, ErrCredentials
	}
	if err != nil {
		return Account{}, err
	}
	a, err := s.passkeyAccount(ctx, id, strings.ToLower(strings.TrimSpace(user)))
	if err != nil {
		return Account{}, err
	}
	// Written at most hourly: a session makes many connections.
	if time.Until(expires) < sessionTokenIdle-time.Hour {
		next := time.Now().Add(sessionTokenIdle)
		if next.After(absolute) {
			next = absolute
		}
		if _, err := s.engine.DB.ExecContext(ctx, `UPDATE mailbox_session_tokens SET expires=$2 WHERE token_hash=$1`, adminTokenHash(token), next); err != nil {
			return Account{}, err
		}
	}
	return a, nil
}

// endSessionToken ends a session when its owner signs out.
func (e *Engine) endSessionToken(ctx context.Context, token string) error {
	_, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_session_tokens WHERE token_hash=$1`, adminTokenHash(token))
	return err
}

// Passkeys lists an account's passkeys.
func (e *Engine) Passkeys(ctx context.Context, account string) ([]PasskeyInfo, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT id,name,host,created,last_used FROM mailbox_passkeys WHERE account=$1 ORDER BY id`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PasskeyInfo{}
	for rows.Next() {
		var p PasskeyInfo
		if err := rows.Scan(&p.ID, &p.Name, &p.Host, &p.Created, &p.LastUsed); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeletePasskey removes one passkey, and the sessions it started go with it.
func (e *Engine) DeletePasskey(ctx context.Context, a Account, id int64) error {
	var name string
	err := e.DB.QueryRowContext(ctx, `DELETE FROM mailbox_passkeys WHERE id=$1 AND account=$2 RETURNING name`, id, a.ID).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	_, err = e.Audit(ctx, mailpolicy.AuditEntry{Actor: a.Address, Source: "webmail", Action: "passkey-remove", Target: a.Address, Detail: name})
	return err
}

// DeletePasskeys removes every passkey an account has, for an administrator
// helping someone locked out, or one recovering a compromised account.
func (e *Engine) DeletePasskeys(ctx context.Context, account string) error {
	_, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_passkeys WHERE account=$1`, account)
	return err
}
