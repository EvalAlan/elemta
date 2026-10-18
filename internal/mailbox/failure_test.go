package mailbox

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

type interruptedBodies struct {
	BodyStore
	after func(string) error
}

func (b interruptedBodies) Put(ctx context.Context, key string, raw []byte) error {
	if err := b.BodyStore.Put(ctx, key, raw); err != nil {
		return err
	}
	return b.after(key)
}
func TestInterruptedPublicationAndFencing(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	for _, expire := range []bool{false, true} {
		var key string
		bodies := interruptedBodies{BodyStore: e.Bodies, after: func(k string) error {
			key = k
			if expire {
				_, err := e.DB.Exec(`UPDATE mailbox_bodies SET expires=now()-interval '1 hour' WHERE key=$1`, k)
				return err
			}
			return errors.New("upload interrupted after durable body write")
		}}
		broken, err := NewEngine(ctx, e.DB, bodies, Config{}.WithDefaults())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := broken.Append(ctx, a.ID, "INBOX", []byte("unpublished"), nil, time.Time{}, ""); err == nil {
			t.Fatal("interrupted or expired upload published")
		}
		f, msgs, err := e.Snapshot(ctx, a.ID, "INBOX")
		if err != nil || len(msgs) != 0 || f.Next != 1 {
			t.Fatalf("failed append changed mailbox: %+v %v %v", f, msgs, err)
		}
		if _, err := e.DB.Exec(`UPDATE mailbox_bodies SET expires=now()-interval '1 hour' WHERE key=$1`, key); err != nil {
			t.Fatal(err)
		}
		if _, err := e.GC(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := e.Bodies.Get(ctx, key, 100); err == nil {
			t.Fatal("orphan survived cleanup")
		}
	}
	if _, err := e.Append(ctx, a.ID, "INBOX", []byte("committed"), nil, time.Time{}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.DB.Exec(`UPDATE mailbox_accounts SET writable=false WHERE id=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Append(ctx, a.ID, "INBOX", []byte("stale owner"), nil, time.Time{}, ""); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("fenced account accepted write: %v", err)
	}
}
func TestAccountAddressReuseIsIsolated(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	if _, err := e.Append(ctx, a.ID, "INBOX", []byte("old owner's private mail"), nil, time.Time{}, ""); err != nil {
		t.Fatal(err)
	}
	replacement := Account{ID: uuid.NewString(), Address: a.Address}
	if err := e.EnsureAccount(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = e.DB.Exec(`DELETE FROM mailbox_folders WHERE account=$1`, replacement.ID)
		_, _ = e.DB.Exec(`DELETE FROM mailbox_accounts WHERE id=$1`, replacement.ID)
	}()
	_, messages, err := e.Snapshot(ctx, replacement.ID, "INBOX")
	if err != nil || len(messages) != 0 {
		t.Fatalf("reused address exposed old mail: %v %v", messages, err)
	}
}
func TestConfigTags(t *testing.T) {
	var inspect func(reflect.Type)
	inspect = func(typ reflect.Type) {
		for i := range typ.NumField() {
			field := typ.Field(i)
			if field.Tag.Get("toml") == "" {
				t.Errorf("%s.%s lacks toml tag", typ.Name(), field.Name)
			}
			if field.Type.Kind() == reflect.Struct {
				inspect(field.Type)
			}
		}
	}
	inspect(reflect.TypeFor[Config]())
}

func TestSynchronousPolicyParsing(t *testing.T) {
	for names, want := range map[string]int{"ANY 1 (a,b)": 1, "FIRST 2 (a,b,c)": 2, "a,b": 1, "*": 1, "any 3 (a,b,c)": 3} {
		n, err := requiredStandbys(names)
		if err != nil || n != want {
			t.Errorf("%q: %d %v", names, n, err)
		}
	}
	for _, names := range []string{"", "ANY 0 (a)", "FIRST 99999999999999999999999 (a)"} {
		if _, err := requiredStandbys(names); err == nil {
			t.Errorf("invalid policy accepted: %q", names)
		}
	}
}
func TestStrictModeDoesNotFallBack(t *testing.T) {
	e, a := testEngine(t)
	e.requireSync = true
	ctx := context.Background()
	if err := e.Ready(ctx); err == nil {
		t.Fatal("standalone database reported synchronous readiness")
	}
	if _, err := e.Append(ctx, a.ID, "INBOX", []byte("must not be acknowledged"), nil, time.Time{}, ""); err == nil {
		t.Fatal("strict write fell back to standalone commit")
	}
	_, messages, err := e.Snapshot(ctx, a.ID, "INBOX")
	if err != nil || len(messages) != 0 {
		t.Fatalf("strict failure exposed mail: %v %v", messages, err)
	}
}
