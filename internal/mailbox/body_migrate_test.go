package mailbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func bodyKeysOf(t *testing.T, e *Engine, a Account) []string {
	t.Helper()
	rows, err := e.DB.Query(`SELECT m.body FROM mailbox_messages m JOIN mailbox_folders f ON f.id=m.folder WHERE f.account=$1 ORDER BY m.uid`, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
	}
	return keys
}

func TestEncryptBodiesMigratesStoredMail(t *testing.T) {
	ctx := context.Background()
	e, a := testEngine(t)
	raw := []byte("From: a@example.com\r\nSubject: old\r\n\r\nstored in the clear\r\n")
	if _, err := e.Append(ctx, a.ID, "INBOX", raw, nil, time.Now(), uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	keys := bodyKeysOf(t, e, a)
	if len(keys) != 1 {
		t.Fatalf("bodies = %v", keys)
	}
	inner := e.Bodies
	if before, err := inner.Get(ctx, keys[0], 1<<20); err != nil || !bytes.Contains(before, []byte("stored in the clear")) {
		t.Fatalf("expected a plaintext body first: %v", err)
	}
	enc := &encryptedBodies{BodyStore: inner, keys: testBodyKeys(t, "v1:"+b64(1))}
	e.Bodies = enc

	// Mail still in the clear reads the same with encryption on.
	if got, err := e.Bodies.Get(ctx, keys[0], int64(len(raw))); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("before migrating: %q, %v", got, err)
	}
	r, err := e.EncryptBodies(ctx, nil)
	if err != nil || len(r.Failed) != 0 || r.Encrypted == 0 {
		t.Fatalf("migrate = %+v, %v", r, err)
	}
	stored, err := inner.Get(ctx, keys[0], 1<<20)
	if err != nil || bytes.Contains(stored, []byte("stored in the clear")) {
		t.Fatalf("still plaintext after migrating: %v", err)
	}
	if got, err := e.Bodies.Get(ctx, keys[0], int64(len(raw))); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("after migrating: %q, %v", got, err)
	}

	// New mail is encrypted from the start, and the checksum-verifying read
	// path and Verify both still agree with the metadata.
	if _, err := e.Append(ctx, a.ID, "INBOX", []byte("From: b@example.com\r\n\r\nnew mail\r\n"), nil, time.Now(), uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	keys = bodyKeysOf(t, e, a)
	newest, err := inner.Get(ctx, keys[len(keys)-1], 1<<20)
	if err != nil || bytes.Contains(newest, []byte("new mail")) {
		t.Fatalf("new mail stored in the clear: %v", err)
	}
	if v, err := e.Verify(ctx, 0, nil); err != nil || len(v.Corrupt) != 0 {
		t.Fatalf("verify = %+v, %v", v.Corrupt, err)
	}

	// A second run changes nothing it already did.
	again, err := e.EncryptBodies(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range again.Failed {
		if strings.HasPrefix(f, keys[0]) {
			t.Fatalf("second run failed on a body: %s", f)
		}
	}

	// Rotating moves it to the new key, and the old key can then go.
	e.Bodies = &encryptedBodies{BodyStore: inner, keys: testBodyKeys(t, "v2:"+b64(2)+",v1:"+b64(1))}
	if _, err = e.EncryptBodies(ctx, nil); err != nil {
		t.Fatal(err)
	}
	e.Bodies = &encryptedBodies{BodyStore: inner, keys: testBodyKeys(t, "v2:"+b64(2))}
	if got, err := e.Bodies.Get(ctx, keys[0], int64(len(raw))); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("after rotating: %q, %v", got, err)
	}
}

// A body that already doesn't match its checksum is reported and left alone:
// encrypting it would bury the damage under a valid seal.
func TestEncryptBodiesLeavesDamagedBodies(t *testing.T) {
	ctx := context.Background()
	e, a := testEngine(t)
	if _, err := e.Append(ctx, a.ID, "INBOX", []byte("From: a@example.com\r\n\r\ndamaged\r\n"), nil, time.Now(), uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	key := bodyKeysOf(t, e, a)[0]
	store := e.Bodies.(*FileBodies)
	wrong := []byte("From: a@example.com\r\n\r\nDAMAGED\r\n")
	if err := store.Replace(ctx, key, wrong); err != nil {
		t.Fatal(err)
	}
	e.Bodies = &encryptedBodies{BodyStore: store, keys: testBodyKeys(t, "v1:"+b64(1))}
	r, err := e.EncryptBodies(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range r.Failed {
		found = found || strings.HasPrefix(f, key)
	}
	if !found {
		t.Fatalf("damaged body not reported: %+v", r)
	}
	if got, err := store.Get(ctx, key, 1<<20); err != nil || !bytes.Equal(got, wrong) {
		t.Fatalf("damaged body changed: %q, %v", got, err)
	}
}

func TestBodyKeyFingerprintGuardsTheStore(t *testing.T) {
	ctx := context.Background()
	e, _ := testEngine(t)
	if _, err := e.DB.Exec(`DELETE FROM mailbox_body_keys`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = e.DB.Exec(`DELETE FROM mailbox_body_keys`) })
	if err := e.checkBodyKeys(ctx, nil); err != nil {
		t.Fatalf("no keys, none ever used: %v", err)
	}
	if err := e.checkBodyKeys(ctx, testBodyKeys(t, "v1:"+b64(1))); err != nil {
		t.Fatal(err)
	}
	if err := e.checkBodyKeys(ctx, testBodyKeys(t, "v1:"+b64(1))); err != nil {
		t.Fatalf("the same key again: %v", err)
	}
	if err := e.checkBodyKeys(ctx, testBodyKeys(t, "v1:"+b64(2))); err == nil {
		t.Fatal("a different key under the same version was accepted")
	}
	if err := e.checkBodyKeys(ctx, nil); err == nil {
		t.Fatal("started without keys on an encrypted store")
	}
	if err := e.checkBodyKeys(ctx, testBodyKeys(t, "v2:"+b64(2)+",v1:"+b64(1))); err != nil {
		t.Fatalf("rotation refused: %v", err)
	}
}
