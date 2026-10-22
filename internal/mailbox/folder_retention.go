package mailbox

import (
	"context"
	"fmt"

	"github.com/EvalAlan/elemta/internal/mailpolicy"
)

// FolderRetention is the user's maximum age for mail in one folder. Zero
// leaves administrator retention in effect, or keeps mail indefinitely.
type FolderRetention struct {
	Name string `json:"name"`
	Days int    `json:"days"`
}

func (e *Engine) FolderRetentions(ctx context.Context, account string) ([]FolderRetention, error) {
	folders, err := e.Folders(ctx, account)
	if err != nil {
		return nil, err
	}
	out := make([]FolderRetention, 0, len(folders))
	for _, folder := range folders {
		out = append(out, FolderRetention{Name: folder.Name, Days: folder.RetentionDays})
	}
	return out, nil
}

func (e *Engine) SetFolderRetentions(ctx context.Context, account string, settings []FolderRetention) ([]FolderRetention, error) {
	if len(settings) == 0 || len(settings) > 100 {
		return nil, fmt.Errorf("%w: choose 1 to 100 folders", mailpolicy.ErrInvalid)
	}
	for i := range settings {
		settings[i].Name = canonicalMailbox(settings[i].Name)
		if !validMailbox(settings[i].Name) || settings[i].Days < 0 || settings[i].Days > 36500 {
			return nil, fmt.Errorf("%w: retention must name a folder and use 0 to 36500 days", mailpolicy.ErrInvalid)
		}
		// Webmail stores settings and calendar data as messages in these
		// folders; expiring them would silently erase user data.
		if retentionDataFolder(settings[i].Name) {
			return nil, fmt.Errorf("%w: retention is unavailable for application data folders", mailpolicy.ErrInvalid)
		}
	}
	tx, err := e.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	for _, setting := range settings {
		res, err := tx.ExecContext(ctx, `UPDATE mailbox_folders SET retention_days=$3 WHERE account=$1 AND name=$2`, account, setting.Name, setting.Days)
		if err != nil {
			return nil, err
		}
		if n, err := res.RowsAffected(); err != nil {
			return nil, err
		} else if n == 0 {
			return nil, ErrNotFound
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return settings, nil
}
