package mailbox

// Incremental folder updates.
//
// A selected IMAP session keeps a view of its folder. Reloading the whole
// folder to learn what changed (after every STORE, and on every IDLE poll
// that sees a new MODSEQ) costs time and memory in proportion to the
// folder, which is fine for a few hundred messages and not for 100,000.
// Every change already writes a mailbox_changes row with the folder's new
// MODSEQ, so a session can instead ask for the UIDs touched since the
// MODSEQ it last saw and load only those rows.
//
// The journal may be trimmed (see CompactChanges); a folder's
// journal_floor records the oldest MODSEQ it can still answer from, and a
// session that fell behind it takes a full snapshot instead.

import (
	"context"
	"database/sql"
	"time"

	"github.com/lib/pq"
)

// FolderChanges is what changed in a folder since a MODSEQ.
type FolderChanges struct {
	Folder Folder
	// Changed holds the current rows of messages appended or re-flagged.
	Changed []Message
	// Gone holds the UIDs of messages that no longer exist.
	Gone []uint32
	// Complete is false when the journal no longer covers the range; the
	// caller must take a full snapshot.
	Complete bool
}

// Changes reports what changed in the folder with this ID since modseq.
func (e *Engine) Changes(ctx context.Context, account string, folderID int64, since uint64) (FolderChanges, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	var out FolderChanges
	tx, err := e.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback() }()
	var floor uint64
	err = tx.QueryRowContext(ctx, `SELECT `+folderCols+`,journal_floor FROM mailbox_folders WHERE account=$1 AND id=$2`, account, folderID).
		Scan(&out.Folder.ID, &out.Folder.Name, &out.Folder.Validity, &out.Folder.Next, &out.Folder.ModSeq, &out.Folder.Subscribed, &floor)
	if err == sql.ErrNoRows {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if since < floor {
		return out, tx.Commit()
	}
	out.Complete = true
	if out.Folder.ModSeq <= since {
		return out, tx.Commit()
	}
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT uid FROM mailbox_changes WHERE folder=$1 AND modseq>$2`, folderID, since)
	if err != nil {
		return out, err
	}
	// database/sql range-checks the BIGINT into uint32.
	var touched []uint32
	for rows.Next() {
		var u uint32
		if err := rows.Scan(&u); err != nil {
			rows.Close()
			return out, err
		}
		touched = append(touched, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}
	if len(touched) > 0 {
		ids := make([]int64, len(touched))
		for i, u := range touched {
			ids[i] = int64(u)
		}
		msgs, err := scanMessagesWhere(ctx, tx, `m.folder=$1 AND m.uid=ANY($2)`, folderID, pq.Array(ids))
		if err != nil {
			return out, err
		}
		present := make(map[uint32]bool, len(msgs))
		for _, m := range msgs {
			present[m.UID] = true
		}
		out.Changed = msgs
		for _, u := range touched {
			if !present[u] {
				out.Gone = append(out.Gone, u)
			}
		}
	}
	return out, tx.Commit()
}

// CompactChanges drops journal rows older than keep, raising each affected
// folder's floor so sessions behind it fall back to a snapshot.
func (e *Engine) CompactChanges(ctx context.Context, keep time.Duration) (int64, error) {
	tx, err := e.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	cutoff := time.Now().Add(-keep)
	if _, err := tx.ExecContext(ctx, `UPDATE mailbox_folders f SET journal_floor=c.top
FROM (SELECT folder,max(modseq) AS top FROM mailbox_changes WHERE created<$1 GROUP BY folder) c
WHERE f.id=c.folder AND c.top>f.journal_floor`, cutoff); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM mailbox_changes WHERE created<$1`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, tx.Commit()
}
