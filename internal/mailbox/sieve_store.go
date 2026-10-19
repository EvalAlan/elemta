package mailbox

// Sieve script storage. Scripts live in Postgres with the rest of the
// account, so every replica sees the same active script and a ManageSieve
// change takes effect for the next delivery anywhere.

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// SieveScript is one stored script.
type SieveScript struct {
	Name    string
	Script  string
	Active  bool
	Updated time.Time
}

var (
	ErrScriptActive = errors.New("mailbox: the active script can't be deleted")
	ErrScriptLimit  = errors.New("mailbox: too many scripts")
)

func (e *Engine) Scripts(ctx context.Context, account string) ([]SieveScript, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT name,'',active,updated FROM mailbox_sieve_scripts WHERE account=$1 ORDER BY name`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SieveScript
	for rows.Next() {
		var s SieveScript
		if err := rows.Scan(&s.Name, &s.Script, &s.Active, &s.Updated); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (e *Engine) Script(ctx context.Context, account, name string) (SieveScript, error) {
	var s SieveScript
	err := e.DB.QueryRowContext(ctx, `SELECT name,script,active,updated FROM mailbox_sieve_scripts WHERE account=$1 AND name=$2`, account, name).
		Scan(&s.Name, &s.Script, &s.Active, &s.Updated)
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrNotFound
	}
	return s, err
}

// ActiveScript returns the account's active script, or ErrNotFound.
func (e *Engine) ActiveScript(ctx context.Context, account string) (SieveScript, error) {
	var s SieveScript
	err := e.DB.QueryRowContext(ctx, `SELECT name,script,active,updated FROM mailbox_sieve_scripts WHERE account=$1 AND active`, account).
		Scan(&s.Name, &s.Script, &s.Active, &s.Updated)
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrNotFound
	}
	return s, err
}

// PutScript creates or replaces a script, keeping its active state.
func (e *Engine) PutScript(ctx context.Context, account, name, script string, maxScripts int) error {
	return e.tx(ctx, account, func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mailbox_sieve_scripts WHERE account=$1 AND name=$2)`, account, name).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM mailbox_sieve_scripts WHERE account=$1`, account).Scan(&n); err != nil {
				return err
			}
			if n >= maxScripts {
				return ErrScriptLimit
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO mailbox_sieve_scripts(account,name,script) VALUES($1,$2,$3)
ON CONFLICT(account,name) DO UPDATE SET script=EXCLUDED.script,updated=now()`, account, name, script)
		return err
	})
}

// SetActive makes name the active script; an empty name deactivates all.
func (e *Engine) SetActive(ctx context.Context, account, name string) error {
	return e.tx(ctx, account, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE mailbox_sieve_scripts SET active=false,updated=now() WHERE account=$1 AND active`, account); err != nil {
			return err
		}
		if name == "" {
			return nil
		}
		res, err := tx.ExecContext(ctx, `UPDATE mailbox_sieve_scripts SET active=true,updated=now() WHERE account=$1 AND name=$2`, account, name)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func (e *Engine) DeleteScript(ctx context.Context, account, name string) error {
	return e.tx(ctx, account, func(tx *sql.Tx) error {
		var active bool
		err := tx.QueryRowContext(ctx, `SELECT active FROM mailbox_sieve_scripts WHERE account=$1 AND name=$2`, account, name).Scan(&active)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if active {
			return ErrScriptActive
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM mailbox_sieve_scripts WHERE account=$1 AND name=$2`, account, name)
		return err
	})
}

func (e *Engine) RenameScript(ctx context.Context, account, old, newName string) error {
	return e.tx(ctx, account, func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mailbox_sieve_scripts WHERE account=$1 AND name=$2)`, account, newName).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrExists
		}
		res, err := tx.ExecContext(ctx, `UPDATE mailbox_sieve_scripts SET name=$3,updated=now() WHERE account=$1 AND name=$2`, account, old, newName)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// claimSent records a side effect (a redirect or an automatic reply) so
// it happens once: it reports false when key was already claimed and
// hasn't expired.
func (e *Engine) claimSent(ctx context.Context, account, key string, ttl time.Duration) (bool, error) {
	res, err := e.DB.ExecContext(ctx, `INSERT INTO mailbox_sieve_sent(account,key,expires) VALUES($1,$2,now()+$3*interval '1 second')
ON CONFLICT(account,key) DO UPDATE SET expires=EXCLUDED.expires WHERE mailbox_sieve_sent.expires<now()`, account, key, int64(ttl/time.Second))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// redirectSent only observes completed redirects. A redirect is recorded
// after SMTP accepts it, so a crashed sender cannot leave a false success.
func (e *Engine) redirectSent(ctx context.Context, account, key string) (bool, error) {
	var sent bool
	err := e.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mailbox_sieve_sent WHERE account=$1 AND key=$2 AND expires>now())`, account, key).Scan(&sent)
	return sent, err
}

// releaseSent undoes a claim whose side effect failed, so a retry can try
// again.
func (e *Engine) releaseSent(ctx context.Context, account, key string) {
	_, _ = e.DB.ExecContext(ctx, `DELETE FROM mailbox_sieve_sent WHERE account=$1 AND key=$2`, account, key)
}
