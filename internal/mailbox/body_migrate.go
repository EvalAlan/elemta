package mailbox

import (
	"context"
	"errors"
	"fmt"
)

// BodyReplacer overwrites a stored body. Only moving bodies between encryption
// states needs it: everything else treats bodies as write-once.
type BodyReplacer interface {
	Replace(context.Context, string, []byte) error
}

// EncryptReport is the result of EncryptBodies.
type EncryptReport struct {
	Checked, Encrypted int
	// Failed lists bodies left as they were, because they couldn't be read
	// or didn't match their recorded checksum.
	Failed []string
}

// EncryptBodies brings every body onto the current key: plaintext ones, and
// after a rotation those on older keys. It is safe to stop and run again, and
// safe while the service runs, because a reader takes either form and each
// object is replaced whole. Every body is checked against its recorded
// checksum first and read back after, so a body already damaged is reported
// rather than sealed in that state.
func (e *Engine) EncryptBodies(ctx context.Context, progress func(done int)) (EncryptReport, error) {
	var r EncryptReport
	enc, ok := e.Bodies.(*encryptedBodies)
	if !ok {
		return r, errors.New("ELEMTA_MAILBOX_BODY_KEYS is not set")
	}
	replace, ok := enc.BodyStore.(BodyReplacer)
	if !ok {
		return r, errors.New("this body store can't replace bodies")
	}
	rows, err := e.DB.QueryContext(ctx, `SELECT key,size,checksum FROM mailbox_bodies WHERE store=$1 AND state='ready' ORDER BY key`, enc.Identity())
	if err != nil {
		return r, err
	}
	var todo []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.Body, &m.Size, &m.Checksum); err != nil {
			_ = rows.Close()
			return r, err
		}
		todo = append(todo, m)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return r, err
	}
	for _, m := range todo {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		r.Checked++
		if progress != nil && r.Checked%1000 == 0 {
			progress(r.Checked)
		}
		changed, err := e.encryptBody(ctx, enc, replace, m)
		switch {
		case err != nil:
			r.Failed = append(r.Failed, fmt.Sprintf("%s: %v", m.Body, err))
		case changed:
			r.Encrypted++
		}
	}
	return r, nil
}

func (e *Engine) encryptBody(ctx context.Context, enc *encryptedBodies, replace BodyReplacer, m Message) (bool, error) {
	stored, err := enc.BodyStore.Get(ctx, m.Body, m.Size+bodyOverhead)
	if err != nil {
		return false, err
	}
	version, sealed, err := bodyVersion(stored)
	if err != nil {
		return false, err
	}
	if sealed && version == enc.current() {
		return false, nil
	}
	plain, err := enc.open(m.Body, stored)
	if err != nil {
		return false, err
	}
	if int64(len(plain)) != m.Size || checksumOf(plain) != m.Checksum {
		return false, errors.New("doesn't match its recorded checksum")
	}
	next, err := enc.seal(m.Body, plain)
	if err != nil {
		return false, err
	}
	// Garbage collection may have retired it since the list was read, and a
	// replace would put a deleted message back.
	var state string
	if err := e.DB.QueryRowContext(ctx, `SELECT state FROM mailbox_bodies WHERE key=$1`, m.Body).Scan(&state); err != nil {
		return false, err
	}
	if state != "ready" {
		return false, nil
	}
	if err := replace.Replace(ctx, m.Body, next); err != nil {
		return false, err
	}
	check, err := enc.Get(ctx, m.Body, m.Size)
	if err != nil {
		return false, fmt.Errorf("reading it back: %w", err)
	}
	if checksumOf(check) != m.Checksum {
		return false, errors.New("reading it back gave different contents")
	}
	return true, nil
}
