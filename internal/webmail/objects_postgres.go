package webmail

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// postgresObjects scopes every operation to one authenticated mailbox. The
// caller owns the shared pool; closing an IMAP session must not close it.
type postgresObjects struct {
	db   *sql.DB
	user string
}

var _ ObjectStore = postgresObjects{}

type postgresMailstore struct {
	Mailstore
	objects postgresObjects
}

func (s postgresMailstore) Objects(ctx context.Context, c Collection) ([]Object, error) {
	return s.objects.Objects(ctx, c)
}
func (s postgresMailstore) PutObject(ctx context.Context, c Collection, obj Object) error {
	return s.objects.PutObject(ctx, c, obj)
}
func (s postgresMailstore) DeleteObject(ctx context.Context, c Collection, id string) error {
	return s.objects.DeleteObject(ctx, c, id)
}

func postgresObjectDialer(db *sql.DB, cfg Config, dial Dialer) Dialer {
	return func(ctx context.Context, user, password string) (Mailstore, error) {
		st, err := dial(ctx, user, password)
		if err != nil {
			return nil, err
		}
		objects := postgresObjects{db: db, user: strings.ToLower(cfg.address(user))}
		if err := objects.migrate(ctx, st); err != nil {
			_ = st.Close()
			return nil, fmt.Errorf("webmail: object migration failed: %w", err)
		}
		return postgresMailstore{Mailstore: st, objects: objects}, nil
	}
}

// initObjectSchema is deliberately separate from opening the pool so startup
// can fail before accepting requests if the schema cannot be installed.
func initObjectSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS webmail_object_users (
		mailbox TEXT PRIMARY KEY,
		migrated BOOLEAN NOT NULL DEFAULT FALSE
	);
	CREATE TABLE IF NOT EXISTS webmail_objects (
		mailbox TEXT NOT NULL REFERENCES webmail_object_users(mailbox),
		collection TEXT NOT NULL,
		id TEXT NOT NULL,
		name TEXT NOT NULL DEFAULT '',
		title TEXT NOT NULL,
		content_type TEXT NOT NULL,
		data BYTEA NOT NULL,
		modified TIMESTAMPTZ NOT NULL,
		PRIMARY KEY (mailbox, collection, id)
	);
	CREATE UNIQUE INDEX IF NOT EXISTS webmail_objects_name
		ON webmail_objects(mailbox, collection, name) WHERE name <> ''`)
	return err
}

func validCollection(c Collection) bool {
	for _, known := range collections {
		if c == known {
			return true
		}
	}
	return false
}

func (s postgresObjects) Objects(ctx context.Context, c Collection) ([]Object, error) {
	if !validCollection(c) {
		return nil, errors.New("webmail: invalid object collection")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, title, content_type, data, modified
		FROM webmail_objects WHERE mailbox=$1 AND collection=$2 ORDER BY id`, s.user, c)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var objects []Object
	for rows.Next() {
		var obj Object
		if err := rows.Scan(&obj.ID, &obj.Name, &obj.Title, &obj.ContentType, &obj.Data, &obj.Modified); err != nil {
			return nil, err
		}
		objects = append(objects, obj)
	}
	return objects, rows.Err()
}

type objectExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func putPostgresObject(ctx context.Context, exec objectExecutor, user string, c Collection, obj Object) error {
	if !validCollection(c) {
		return errors.New("webmail: invalid object collection")
	}
	if obj.Modified.IsZero() {
		obj.Modified = time.Now().UTC()
	}
	if obj.Data == nil {
		obj.Data = []byte{}
	}
	_, err := exec.ExecContext(ctx, `INSERT INTO webmail_objects
		(mailbox, collection, id, name, title, content_type, data, modified)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (mailbox, collection, id) DO UPDATE SET
		name=CASE WHEN EXCLUDED.name='' THEN webmail_objects.name ELSE EXCLUDED.name END,
		title=EXCLUDED.title, content_type=EXCLUDED.content_type,
		data=EXCLUDED.data, modified=EXCLUDED.modified`,
		user, c, objectID(obj.ID), obj.Name, obj.Title, obj.ContentType, obj.Data, obj.Modified)
	return err
}

func (s postgresObjects) PutObject(ctx context.Context, c Collection, obj Object) error {
	// Modified is the last write time, even when the caller read an older
	// version first. Migration alone preserves the source timestamp.
	obj.Modified = time.Now().UTC()
	return putPostgresObject(ctx, s.db, s.user, c, obj)
}

func (s postgresObjects) DeleteObject(ctx context.Context, c Collection, id string) error {
	if !validCollection(c) {
		return errors.New("webmail: invalid object collection")
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM webmail_objects WHERE mailbox=$1 AND collection=$2 AND id=$3`, s.user, c, objectID(id))
	return err
}

// migrate copies all four collections in one transaction and keeps the IMAP
// originals for rollback. A durable per-mailbox row serializes first logins
// across replicas; completed migrations never resurrect deleted SQL objects.
// All writers must switch to SQL together during a maintenance window.
func (s postgresObjects) migrate(ctx context.Context, source ObjectStore) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // a committed transaction makes this a no-op
	if _, err := tx.ExecContext(ctx, `INSERT INTO webmail_object_users(mailbox) VALUES ($1) ON CONFLICT DO NOTHING`, s.user); err != nil {
		return err
	}
	var migrated bool
	if err := tx.QueryRowContext(ctx, `SELECT migrated FROM webmail_object_users WHERE mailbox=$1 FOR UPDATE`, s.user).Scan(&migrated); err != nil {
		return err
	}
	if migrated {
		return tx.Commit()
	}
	for _, c := range collections {
		objects, err := source.Objects(ctx, c)
		if err != nil {
			return fmt.Errorf("webmail: migrate %s: %w", c, err)
		}
		for _, obj := range objects {
			if err := putPostgresObject(ctx, tx, s.user, c, obj); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE webmail_object_users SET migrated=TRUE WHERE mailbox=$1`, s.user); err != nil {
		return err
	}
	return tx.Commit()
}
