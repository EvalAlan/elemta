package mailbox

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

type memBodies struct {
	objects map[string][]byte
	checks  int
}

func (m *memBodies) Identity() string { return "memory" }
func (m *memBodies) Put(_ context.Context, key string, data []byte) error {
	if _, ok := m.objects[key]; ok {
		return errors.New("exists")
	}
	m.objects[key] = bytes.Clone(data)
	return nil
}
func (m *memBodies) Replace(_ context.Context, key string, data []byte) error {
	m.objects[key] = bytes.Clone(data)
	return nil
}
func (m *memBodies) Get(_ context.Context, key string, max int64) ([]byte, error) {
	data, ok := m.objects[key]
	if !ok {
		return nil, errors.New("missing")
	}
	if int64(len(data)) > max {
		return nil, ErrTooLarge
	}
	return data, nil
}
func (m *memBodies) Delete(_ context.Context, key string) error { delete(m.objects, key); return nil }
func (m *memBodies) Check(context.Context) error                { m.checks++; return nil }
func (m *memBodies) Close() error                               { return nil }

func testBodyKeys(t *testing.T, value string) []bodySecret {
	t.Helper()
	keys, err := parseBodyKeys(value)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func b64(fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, bodyKeySize))
}

const testBodyID = "0123456789abcdef0123456789abcdef"

func TestBodyEncryptionRoundTrip(t *testing.T) {
	ctx := context.Background()
	inner := &memBodies{objects: map[string][]byte{}}
	e := &encryptedBodies{BodyStore: inner, keys: testBodyKeys(t, "v1:"+b64(1))}
	plain := []byte("Subject: payroll\r\n\r\nthe secret figures\r\n")
	if err := e.Put(ctx, testBodyID, plain); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(inner.objects[testBodyID], []byte("secret figures")) || bytes.Contains(inner.objects[testBodyID], []byte("payroll")) {
		t.Fatal("the store holds plaintext")
	}
	// The limit callers pass is the message's own size, not the sealed one.
	got, err := e.Get(ctx, testBodyID, int64(len(plain)))
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("get = %q, %v", got, err)
	}
	if _, err = e.Get(ctx, testBodyID, int64(len(plain))-1); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over the limit = %v", err)
	}
	if err = e.Check(ctx); err != nil || inner.checks != 1 {
		t.Fatalf("check = %v after %d inner checks", err, inner.checks)
	}
}

func TestEachBodyGetsItsOwnKey(t *testing.T) {
	keys := testBodyKeys(t, "v1:"+b64(1))
	a, err := sealBody(keys[0], testBodyID, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := sealBody(keys[0], testBodyID, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two seals of one body are identical")
	}
}

// A body stored before encryption was turned on has to stay readable until the
// migration reaches it.
func TestPlaintextBodiesStayReadable(t *testing.T) {
	plain := []byte("From: a@example.com\r\n\r\nold mail\r\n")
	inner := &memBodies{objects: map[string][]byte{testBodyID: plain}}
	e := &encryptedBodies{BodyStore: inner, keys: testBodyKeys(t, "v1:"+b64(1))}
	got, err := e.Get(context.Background(), testBodyID, int64(len(plain)))
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("get = %q, %v", got, err)
	}
}

func TestSealedBodyRefusesTampering(t *testing.T) {
	ctx := context.Background()
	const other = "fedcba9876543210fedcba9876543210"
	inner := &memBodies{objects: map[string][]byte{}}
	e := &encryptedBodies{BodyStore: inner, keys: testBodyKeys(t, "v1:"+b64(1))}
	if err := e.Put(ctx, testBodyID, []byte("message")); err != nil {
		t.Fatal(err)
	}
	sealed := inner.objects[testBodyID]
	// Moved to another object: one mailbox's mail served as another's.
	inner.objects[other] = sealed
	if _, err := e.Get(ctx, other, 100); err == nil {
		t.Fatal("a body opened under another object's key")
	}
	flipped := bytes.Clone(sealed)
	flipped[len(flipped)-1] ^= 1
	inner.objects[testBodyID] = flipped
	if _, err := e.Get(ctx, testBodyID, 100); err == nil {
		t.Fatal("a modified body opened")
	}
	inner.objects[testBodyID] = sealed[:len(bodyMagic)+1]
	if _, err := e.Get(ctx, testBodyID, 100); err == nil {
		t.Fatal("a truncated body opened")
	}
}

func TestBodyKeyRotationKeepsOldMailReadable(t *testing.T) {
	ctx := context.Background()
	inner := &memBodies{objects: map[string][]byte{}}
	old := &encryptedBodies{BodyStore: inner, keys: testBodyKeys(t, "v1:"+b64(1))}
	if err := old.Put(ctx, testBodyID, []byte("message")); err != nil {
		t.Fatal(err)
	}
	both := &encryptedBodies{BodyStore: inner, keys: testBodyKeys(t, "v2:"+b64(2)+",v1:"+b64(1))}
	if got, err := both.Get(ctx, testBodyID, 100); err != nil || string(got) != "message" {
		t.Fatalf("get = %q, %v", got, err)
	}
	gone := &encryptedBodies{BodyStore: inner, keys: testBodyKeys(t, "v2:"+b64(2))}
	if _, err := gone.Get(ctx, testBodyID, 100); !errors.Is(err, ErrBodyKeyUnavailable) {
		t.Fatalf("missing key = %v", err)
	}
	wrong := &encryptedBodies{BodyStore: inner, keys: testBodyKeys(t, "v1:"+b64(9))}
	if _, err := wrong.Get(ctx, testBodyID, 100); err == nil {
		t.Fatal("the wrong key opened a body")
	}
}

func TestParseBodyKeysRefusesBadInput(t *testing.T) {
	for _, value := range []string{"nokey", "v1:notbase64!", "v1:" + base64.StdEncoding.EncodeToString([]byte("short")), "v1:" + b64(1) + ",v1:" + b64(2), ":" + b64(1), strings.Repeat("v", 65) + ":" + b64(1)} {
		if _, err := parseBodyKeys(value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
	if keys, err := parseBodyKeys(""); err != nil || keys != nil {
		t.Fatalf("empty = %v, %v", keys, err)
	}
	keys := testBodyKeys(t, "v1:"+b64(1))
	if keys[0].fingerprint() == testBodyKeys(t, "v1:"+b64(2))[0].fingerprint() {
		t.Fatal("different keys share a fingerprint")
	}
	if strings.Contains(keys[0].fingerprint(), b64(1)) {
		t.Fatal("fingerprint holds the key")
	}
}
