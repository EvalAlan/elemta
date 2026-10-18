package mailbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// ImportSnapshot describes an offline, immutable export. Paths are relative to
// the snapshot root; os.Root prevents a manifest from reading outside it.
type ImportSnapshot struct {
	Accounts []ImportAccount `json:"accounts"`
}
type ImportAccount struct {
	Address string         `json:"address"`
	Folders []ImportFolder `json:"folders"`
}
type ImportFolder struct {
	Name       string          `json:"name"`
	Validity   uint32          `json:"uidvalidity"`
	Next       uint32          `json:"uidnext"`
	Subscribed bool            `json:"subscribed"`
	Messages   []ImportMessage `json:"messages"`
}
type ImportMessage struct {
	UID   uint32    `json:"uid"`
	File  string    `json:"file"`
	Flags []string  `json:"flags"`
	Date  time.Time `json:"date"`
}

func ReadImportSnapshot(root *os.Root) (ImportSnapshot, error) {
	var result ImportSnapshot
	file, err := root.Open("manifest.json")
	if err != nil {
		return result, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&result)
	return result, err
}

func importBytes(root *os.Root, message ImportMessage, limit int64) ([]byte, error) {
	f, err := root.Open(message.File)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := readBounded(f, limit)
	if err != nil {
		return nil, err
	}
	// Maildir stores LF while IMAP exposes CRLF. Retain existing CRLF and
	// binary bytes, adding CR only before a bare LF, as the source IMAP does.
	var out bytes.Buffer
	for i, b := range raw {
		if b == '\n' && (i == 0 || raw[i-1] != '\r') {
			out.WriteByte('\r')
		}
		out.WriteByte(b)
	}
	if int64(out.Len()) > limit {
		return nil, ErrTooLarge
	}
	return out.Bytes(), nil
}

// ImportOfflineFolder publishes a whole folder atomically, retaining UID holes
// and UIDNEXT. Reruns accept only an exact match; never merge into live mail.
// Protocol services must remain stopped until every folder has been verified.
func (e *Engine) ImportOfflineFolder(ctx context.Context, account string, source ImportFolder, root *os.Root) error {
	if !validMailbox(source.Name) || canonicalMailbox(source.Name) != source.Name || source.Validity == 0 || source.Next == 0 {
		return errors.New("invalid source folder identity")
	}
	var last uint32
	for _, m := range source.Messages {
		if m.UID <= last || m.UID >= source.Next || m.Date.IsZero() || hasFlag(m.Flags, "\\Recent") {
			return errors.New("invalid or unordered source message")
		}
		last = m.UID
	}
	return e.tx(ctx, account, func(tx *sql.Tx) error {
		f, err := folderTx(ctx, tx, account, source.Name)
		exists := err == nil
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		// Recreated folders must never reuse a validity imported from the source.
		// Sequence gaps on rollback are intentional and harmless.
		if _, err := tx.ExecContext(ctx, `SELECT setval('mailbox_uidvalidity',GREATEST((SELECT last_value FROM mailbox_uidvalidity),$1::bigint))`, source.Validity); err != nil {
			return err
		}
		var messages []Message
		if exists {
			messages, err = scanMessages(ctx, tx, f.ID)
			if err != nil {
				return err
			}
		}
		if len(messages) > 0 {
			if f.Validity != source.Validity || f.Next != source.Next || f.Subscribed != source.Subscribed || len(messages) != len(source.Messages) {
				return errors.New("destination folder differs from snapshot")
			}
			for i, m := range messages {
				src := source.Messages[i]
				raw, err := importBytes(root, src, e.MaxBytes)
				if err != nil {
					return err
				}
				stored, err := e.Read(ctx, m)
				if err != nil {
					return err
				}
				if m.UID != src.UID || !m.Date.Equal(src.Date) || !slices.Equal(normalizeFlags(m.Flags), normalizeFlags(src.Flags)) || !bytes.Equal(stored, raw) {
					return errors.New("destination message differs from snapshot")
				}
			}
			return nil
		}
		// A fresh EnsureAccount creates an empty INBOX. Any other empty folder
		// can be imported safely only while the operator holds the offline window.
		if !exists {
			if err := tx.QueryRowContext(ctx, `INSERT INTO mailbox_folders(account,name) VALUES($1,$2) RETURNING id`, account, source.Name).Scan(&f.ID); err != nil {
				return err
			}
		}
		var added int64
		for _, m := range source.Messages {
			raw, err := importBytes(root, m, e.MaxBytes)
			if err != nil {
				return fmt.Errorf("UID %d: %w", m.UID, err)
			}
			sum := sha256.Sum256(raw)
			hash := hex.EncodeToString(sum[:])
			key := strings.ReplaceAll(uuid.NewString(), "-", "")
			// Staging survives rollback, so interrupted imports leave reclaimable
			// bodies rather than untracked files. Publication locks the upload lease.
			if _, err := e.DB.ExecContext(ctx, `INSERT INTO mailbox_bodies(key,size,checksum,store) VALUES($1,$2,$3,$4)`, key, len(raw), hash, e.Bodies.Identity()); err != nil {
				return err
			}
			if err := e.Bodies.Put(ctx, key, raw); err != nil {
				return err
			}
			result, err := tx.ExecContext(ctx, `UPDATE mailbox_bodies SET state='ready' WHERE key=$1 AND state='staging' AND expires>now()`, key)
			if err != nil {
				return err
			}
			n, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if n != 1 {
				return errors.New("import upload lease expired")
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO mailbox_messages(folder,uid,body,flags,internal_date,modseq) VALUES($1,$2,$3,$4,$5,1)`, f.ID, m.UID, key, pq.Array(normalizeFlags(m.Flags)), m.Date); err != nil {
				return err
			}
			added += int64(len(raw))
		}
		if _, err := tx.ExecContext(ctx, `UPDATE mailbox_folders SET uidvalidity=$2,next_uid=$3,subscribed=$4,modseq=1 WHERE id=$1`, f.ID, source.Validity, source.Next, source.Subscribed); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE mailbox_accounts SET used_bytes=used_bytes+$2 WHERE id=$1`, account, added)
		return err
	})
}
