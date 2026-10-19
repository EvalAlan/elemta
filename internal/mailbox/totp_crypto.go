package mailbox

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

type totpKey struct {
	version string
	aead    cipher.AEAD
}

// The first key encrypts new material. Older versions stay in the list until
// every replica and backup that may need them has been rotated.
func parseTOTPKeys(value string) ([]totpKey, error) {
	if value == "" {
		return nil, nil
	}
	var keys []totpKey
	seen := map[string]bool{}
	for _, entry := range strings.Split(value, ",") {
		version, encoded, ok := strings.Cut(strings.TrimSpace(entry), ":")
		if !ok || version == "" || strings.ContainsAny(version, ":,") || seen[version] {
			return nil, errors.New("invalid or duplicate TOTP key version")
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(raw) != 32 {
			return nil, errors.New("TOTP key must be 32 base64-encoded bytes")
		}
		block, err := aes.NewCipher(raw)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		keys = append(keys, totpKey{version: version, aead: aead})
		seen[version] = true
	}
	return keys, nil
}

func (e *Engine) sealTOTP(account, purpose, secret string) (string, error) {
	if len(e.totpKeys) == 0 {
		return "", errors.New("ELEMTA_MAILBOX_TOTP_KEYS is required for two-step verification")
	}
	key := e.totpKeys[0]
	nonce := make([]byte, key.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := key.aead.Seal(nil, nonce, []byte(secret), []byte(account+"\x00"+purpose))
	return "enc:" + key.version + ":" + base64.StdEncoding.EncodeToString(append(nonce, ciphertext...)), nil
}

func (e *Engine) openTOTP(account, purpose, stored string) (string, error) {
	if !strings.HasPrefix(stored, "enc:") {
		return "", errors.New("unencrypted TOTP secret remains")
	}
	version, encoded, ok := strings.Cut(strings.TrimPrefix(stored, "enc:"), ":")
	if !ok {
		return "", errors.New("invalid TOTP ciphertext")
	}
	for _, key := range e.totpKeys {
		if key.version != version {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(data) < key.aead.NonceSize()+key.aead.Overhead() {
			return "", errors.New("invalid TOTP ciphertext")
		}
		plain, err := key.aead.Open(nil, data[:key.aead.NonceSize()], data[key.aead.NonceSize():], []byte(account+"\x00"+purpose))
		if err != nil {
			return "", errors.New("TOTP ciphertext authentication failed")
		}
		return string(plain), nil
	}
	return "", fmt.Errorf("TOTP key version %q is unavailable", version)
}

// Startup migrates plaintext and old-key rows while the schema advisory lock
// excludes another replica's migration. An unavailable key blocks startup.
func (e *Engine) migrateTOTPSecrets(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT account,totp_secret,totp_pending FROM mailbox_security WHERE totp_secret IS NOT NULL OR totp_pending IS NOT NULL FOR UPDATE`)
	if err != nil {
		return err
	}
	type row struct {
		account         string
		active, pending sql.NullString
	}
	var all []row
	for rows.Next() {
		var item row
		if err := rows.Scan(&item.account, &item.active, &item.pending); err != nil {
			_ = rows.Close()
			return err
		}
		all = append(all, item)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	for _, item := range all {
		if len(e.totpKeys) == 0 {
			return errors.New("ELEMTA_MAILBOX_TOTP_KEYS is required for existing two-step verification")
		}
		for _, part := range []struct {
			purpose string
			value   sql.NullString
		}{
			{"active", item.active}, {"pending", item.pending},
		} {
			if !part.value.Valid || strings.HasPrefix(part.value.String, "enc:"+e.totpKeys[0].version+":") {
				continue
			}
			plain := part.value.String
			if strings.HasPrefix(plain, "enc:") {
				plain, err = e.openTOTP(item.account, part.purpose, plain)
				if err != nil {
					return err
				}
			}
			sealed, err := e.sealTOTP(item.account, part.purpose, plain)
			if err != nil {
				return err
			}
			var updateErr error
			if part.purpose == "pending" {
				_, updateErr = tx.ExecContext(ctx, `UPDATE mailbox_security SET totp_pending=$2 WHERE account=$1`, item.account, sealed)
			} else {
				_, updateErr = tx.ExecContext(ctx, `UPDATE mailbox_security SET totp_secret=$2 WHERE account=$1`, item.account, sealed)
			}
			if updateErr != nil {
				return updateErr
			}
		}
	}
	return nil
}
