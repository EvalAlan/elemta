package mailbox

// Queries behind the IMAP session's compact view.
//
// A selected session keeps only the folder's UIDs, which is what sequence
// numbers need: 4 bytes a message, so a thousand sessions on a
// 100,000-message folder hold 400 MB less than they would with full rows.
// Flags, dates, sizes and body keys are loaded for the messages a command
// touches, in batches.

import (
	"context"
	"database/sql"
	"time"

	"github.com/lib/pq"
)

// SelectInfo is what SELECT and EXAMINE report.
type SelectInfo struct {
	Folder Folder
	UIDs   []uint32
	// FirstUnseen is the lowest UID without \Seen, 0 when all are seen.
	FirstUnseen uint32
	// Keywords are the flags in use beyond the system ones.
	Keywords []string
}

func (e *Engine) SelectFolder(ctx context.Context, account, name string) (SelectInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	var out SelectInfo
	tx, err := e.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback() }()
	if out.Folder, err = folderTx(ctx, tx, account, name); err != nil {
		return out, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT uid FROM mailbox_messages WHERE folder=$1 ORDER BY uid`, out.Folder.ID)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var u uint32
		if err := rows.Scan(&u); err != nil {
			rows.Close()
			return out, err
		}
		out.UIDs = append(out.UIDs, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}
	var first sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT min(uid) FROM mailbox_messages WHERE folder=$1 AND NOT ('\seen'=ANY(flags))`, out.Folder.ID).Scan(&first); err != nil {
		return out, err
	}
	if first.Valid && first.Int64 > 0 && first.Int64 <= 1<<32-1 {
		out.FirstUnseen = uint32(first.Int64)
	}
	if err := tx.QueryRowContext(ctx, `SELECT coalesce(array_agg(DISTINCT f),'{}') FROM mailbox_messages, unnest(flags) f WHERE folder=$1 AND left(f,1)<>'\'`, out.Folder.ID).Scan(pq.Array(&out.Keywords)); err != nil {
		return out, err
	}
	return out, tx.Commit()
}

// FolderStatus counts a folder without loading its messages.
func (e *Engine) FolderStatus(ctx context.Context, account, name string) (f Folder, messages, unseen uint32, size int64, err error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if f, err = e.Folder(ctx, account, name); err != nil {
		return
	}
	err = e.DB.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER (WHERE NOT ('\seen'=ANY(m.flags))),coalesce(sum(b.size),0)
FROM mailbox_messages m JOIN mailbox_bodies b ON b.key=m.body WHERE m.folder=$1`, f.ID).Scan(&messages, &unseen, &size)
	return
}

// MessagesByUID loads the current rows of the given UIDs. Messages that no
// longer exist are missing from the result.
func (e *Engine) MessagesByUID(ctx context.Context, folder int64, uids []uint32) (map[uint32]Message, error) {
	out := make(map[uint32]Message, len(uids))
	if len(uids) == 0 {
		return out, nil
	}
	lo, hi := uids[0], uids[0]
	want := make(map[uint32]bool, len(uids))
	for _, u := range uids {
		lo, hi = min(lo, u), max(hi, u)
		want[u] = true
	}
	var msgs []Message
	var err error
	if uint64(hi-lo) < 4*uint64(len(uids)) {
		// Dense, as batches of consecutive sequence numbers are: an index
		// range scan beats matching a long array.
		msgs, err = scanMessagesWhere(ctx, e.DB, `m.folder=$1 AND m.uid BETWEEN $2 AND $3`, folder, int64(lo), int64(hi))
	} else {
		ids := make([]int64, len(uids))
		for i, u := range uids {
			ids[i] = int64(u)
		}
		msgs, err = scanMessagesWhere(ctx, e.DB, `m.folder=$1 AND m.uid=ANY($2)`, folder, pq.Array(ids))
	}
	if err != nil {
		return nil, err
	}
	for _, m := range msgs {
		if want[m.UID] {
			out[m.UID] = m
		}
	}
	return out, nil
}
