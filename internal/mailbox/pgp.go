package mailbox

// PGP keys. Encryption happens in the browser (internal/webmail/static): this
// only keeps keys. It holds someone's public key, so colleagues can find it, and
// their private key locked under a passphrase, so any of their devices can fetch
// it. The passphrase never reaches the server, and a private key that isn't
// locked is refused, because storing one would quietly undo the whole point.
//
// Replacing or removing a key takes the account password. A session alone
// mustn't be able to swap someone's key for one an intruder holds.
//
// Pins remember the key last seen for an address, per user, so a key that
// changes is noticed. They defend against a mistake or a tampered directory
// entry from elsewhere, not against this server, which could lie about both.

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- required by the Web Key Directory hash, not used for security
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
	"github.com/ProtonMail/go-crypto/openpgp"
)

const maxPGPKey = 64 << 10

var errPGPKey = &requestError{"that isn't a usable PGP key for this address"}

// PGPKey is an account's key. PrivateKey is locked with its owner's passphrase.
type PGPKey struct {
	Address     string    `json:"address"`
	Fingerprint string    `json:"fingerprint"`
	PublicKey   string    `json:"public_key"`
	PrivateKey  string    `json:"private_key,omitempty"`
	Created     time.Time `json:"created"`
	// Published says the key is in the public Web Key Directory. It's the
	// owner's choice, because a directory answer tells anyone who guesses an
	// address that it has a key. Colleagues find it either way, or they
	// couldn't encrypt to each other.
	Published bool `json:"published"`
}

// PGPPin is the key a user last accepted for an address.
type PGPPin struct {
	Address     string `json:"address"`
	Fingerprint string `json:"fingerprint"`
}

// checkPGPKey parses a key pair and returns the fingerprint. The private half
// has to be locked throughout, and the key has to name this address, since
// people will encrypt to it because of what it says.
func checkPGPKey(address, public, private string) (string, error) {
	if len(public) > maxPGPKey || len(private) > maxPGPKey {
		return "", errPGPKey
	}
	entities, err := openpgp.ReadArmoredKeyRing(strings.NewReader(public))
	if err != nil || len(entities) != 1 {
		return "", errPGPKey
	}
	entity := entities[0]
	if entity.PrivateKey != nil {
		return "", errPGPKey
	}
	named := false
	for _, id := range entity.Identities {
		named = named || strings.EqualFold(id.UserId.Email, address)
	}
	if !named {
		return "", errPGPKey
	}
	fingerprint := strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint))
	secrets, err := openpgp.ReadArmoredKeyRing(strings.NewReader(private))
	if err != nil || len(secrets) != 1 {
		return "", errPGPKey
	}
	secret := secrets[0]
	if secret.PrivateKey == nil || !secret.PrivateKey.Encrypted || !bytes.Equal(secret.PrimaryKey.Fingerprint, entity.PrimaryKey.Fingerprint) {
		return "", errPGPKey
	}
	for _, sub := range secret.Subkeys {
		if sub.PrivateKey == nil || !sub.PrivateKey.Encrypted {
			return "", errPGPKey
		}
	}
	return fingerprint, nil
}

// wkdHash is the Web Key Directory's name for a local part (RFC draft-koch):
// SHA-1, in z-base-32.
func wkdHash(local string) string {
	sum := sha1.Sum([]byte(strings.ToLower(local))) // #nosec G401 -- the format requires it
	const alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
	var out strings.Builder
	var buffer uint64
	bits := 0
	for _, b := range sum {
		buffer = buffer<<8 | uint64(b)
		bits += 8
		for bits >= 5 {
			out.WriteByte(alphabet[(buffer>>(bits-5))&31])
			bits -= 5
		}
	}
	if bits > 0 {
		out.WriteByte(alphabet[(buffer<<(5-bits))&31])
	}
	return out.String()
}

// PutPGPKey stores an account's key, replacing any it has.
func (e *Engine) PutPGPKey(ctx context.Context, a Account, public, private string) (PGPKey, error) {
	address := strings.ToLower(a.Address)
	fingerprint, err := checkPGPKey(address, public, private)
	if err != nil {
		return PGPKey{}, err
	}
	key := PGPKey{Address: address, Fingerprint: fingerprint, PublicKey: public}
	local := address[:strings.LastIndexByte(address, '@')]
	domain := address[strings.LastIndexByte(address, '@')+1:]
	err = e.DB.QueryRowContext(ctx, `INSERT INTO mailbox_pgp_keys(account,address,domain,wkd_hash,fingerprint,public_key,private_key) VALUES($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT(account) DO UPDATE SET address=EXCLUDED.address,domain=EXCLUDED.domain,wkd_hash=EXCLUDED.wkd_hash,fingerprint=EXCLUDED.fingerprint,public_key=EXCLUDED.public_key,private_key=EXCLUDED.private_key,created=now()
RETURNING created,published`, a.ID, address, domain, wkdHash(local), fingerprint, public, private).Scan(&key.Created, &key.Published)
	if err != nil {
		return PGPKey{}, err
	}
	_, err = e.Audit(ctx, mailpolicy.AuditEntry{Actor: a.Address, Source: "webmail", Action: "pgp-key-set", Target: a.Address, Detail: fingerprint})
	return key, err
}

// PGPKeyOf returns an account's key with its locked private half, nil if none.
func (e *Engine) PGPKeyOf(ctx context.Context, account string) (*PGPKey, error) {
	var k PGPKey
	err := e.DB.QueryRowContext(ctx, `SELECT address,fingerprint,public_key,private_key,created,published FROM mailbox_pgp_keys WHERE account=$1`, account).
		Scan(&k.Address, &k.Fingerprint, &k.PublicKey, &k.PrivateKey, &k.Created, &k.Published)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &k, err
}

// DeletePGPKey removes an account's key. Mail already encrypted to it can't be
// read again unless its owner has a copy, which the webmail warns about.
func (e *Engine) DeletePGPKey(ctx context.Context, a Account) error {
	if _, err := e.DB.ExecContext(ctx, `DELETE FROM mailbox_pgp_keys WHERE account=$1`, a.ID); err != nil {
		return err
	}
	_, err := e.Audit(ctx, mailpolicy.AuditEntry{Actor: a.Address, Source: "webmail", Action: "pgp-key-remove", Target: a.Address})
	return err
}

// SetPGPPublished records whether an account's key is in the public directory.
func (e *Engine) SetPGPPublished(ctx context.Context, a Account, published bool) error {
	res, err := e.DB.ExecContext(ctx, `UPDATE mailbox_pgp_keys SET published=$2 WHERE account=$1`, a.ID, published)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	detail := "not published"
	if published {
		detail = "published"
	}
	_, err = e.Audit(ctx, mailpolicy.AuditEntry{Actor: a.Address, Source: "webmail", Action: "pgp-key-publish", Target: a.Address, Detail: detail})
	return err
}

// PGPLookup returns the public keys of local addresses. An address without one
// is simply left out, so this can't be used to learn who exists.
func (e *Engine) PGPLookup(ctx context.Context, addresses []string) ([]PGPKey, error) {
	out := []PGPKey{}
	for _, address := range addresses {
		var k PGPKey
		err := e.DB.QueryRowContext(ctx, `SELECT address,fingerprint,public_key FROM mailbox_pgp_keys WHERE address=$1`, strings.ToLower(strings.TrimSpace(address))).
			Scan(&k.Address, &k.Fingerprint, &k.PublicKey)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// WKDKey finds a key for the Web Key Directory, and is public: it's what
// publishing a key means.
func (e *Engine) WKDKey(ctx context.Context, domain, hash string) (string, error) {
	var public string
	err := e.DB.QueryRowContext(ctx, `SELECT public_key FROM mailbox_pgp_keys WHERE domain=$1 AND wkd_hash=$2 AND published`, strings.ToLower(domain), hash).Scan(&public)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return public, err
}

// PGPPins lists the keys a user has accepted.
func (e *Engine) PGPPins(ctx context.Context, account string) ([]PGPPin, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT address,fingerprint FROM mailbox_pgp_pins WHERE account=$1 ORDER BY address`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PGPPin{}
	for rows.Next() {
		var p PGPPin
		if err := rows.Scan(&p.Address, &p.Fingerprint); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PutPGPPin records the key a user accepted for an address.
func (e *Engine) PutPGPPin(ctx context.Context, account string, p PGPPin) error {
	address, fingerprint := strings.ToLower(strings.TrimSpace(p.Address)), strings.ToUpper(strings.TrimSpace(p.Fingerprint))
	if !strings.Contains(address, "@") || len(address) > 320 || len(fingerprint) < 32 || len(fingerprint) > 64 {
		return errBadRequest
	}
	if _, err := hex.DecodeString(fingerprint); err != nil {
		return errBadRequest
	}
	_, err := e.DB.ExecContext(ctx, `INSERT INTO mailbox_pgp_pins(account,address,fingerprint) VALUES($1,$2,$3)
ON CONFLICT(account,address) DO UPDATE SET fingerprint=EXCLUDED.fingerprint`, account, address, fingerprint)
	return err
}
