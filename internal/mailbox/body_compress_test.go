package mailbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func letter() []byte {
	return []byte("From: a@example.com\r\nSubject: Report\r\n\r\n" + strings.Repeat("The quarterly figures are attached for review.\r\n", 200))
}

func noise(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCompressionShrinksTextOnly(t *testing.T) {
	ctx := context.Background()
	inner := &memBodies{objects: map[string][]byte{}}
	c := &compressedBodies{BodyStore: inner, compress: true}
	text, photo, small := letter(), noise(t, 8192), []byte("Subject: hi\r\n\r\nshort\r\n")
	for key, body := range map[string][]byte{"text": text, "photo": photo, "small": small} {
		if err := c.Put(ctx, key, body); err != nil {
			t.Fatal(err)
		}
		got, err := c.Get(ctx, key, int64(len(body)))
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("%s came back different: %v", key, err)
		}
	}
	if !bytes.HasPrefix(inner.objects["text"], bodyFrame) || len(inner.objects["text"]) >= len(text)/4 {
		t.Fatalf("text stored at %d of %d bytes", len(inner.objects["text"]), len(text))
	}
	if !bytes.Equal(inner.objects["photo"], photo) || !bytes.Equal(inner.objects["small"], small) {
		t.Fatal("something that doesn't benefit was compressed anyway")
	}
}

// Turning it off must not strand what's already compressed.
func TestCompressedMailReadsWithTheSettingOff(t *testing.T) {
	ctx := context.Background()
	inner := &memBodies{objects: map[string][]byte{}}
	if err := (&compressedBodies{BodyStore: inner, compress: true}).Put(ctx, "k", letter()); err != nil {
		t.Fatal(err)
	}
	off := &compressedBodies{BodyStore: inner}
	got, err := off.Get(ctx, "k", int64(len(letter())))
	if err != nil || !bytes.Equal(got, letter()) {
		t.Fatalf("%v", err)
	}
	if err := off.Put(ctx, "n", letter()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(inner.objects["n"], letter()) {
		t.Fatal("compressed with the setting off")
	}
}

// Anyone can APPEND a message that starts like a frame, and it has to come back
// as those bytes, with compression on or off, however it compresses.
func TestAMessageThatLooksLikeAFrame(t *testing.T) {
	ctx := context.Background()
	for _, crafted := range [][]byte{bodyFrame, append(bytes.Clone(bodyFrame), []byte("not zstd")...), append(bytes.Clone(bodyFrame), noise(t, 4096)...)} {
		for _, on := range []bool{true, false} {
			c := &compressedBodies{BodyStore: &memBodies{objects: map[string][]byte{}}, compress: on}
			if err := c.Put(ctx, "k", crafted); err != nil {
				t.Fatal(err)
			}
			got, err := c.Get(ctx, "k", int64(len(crafted)))
			if err != nil || !bytes.Equal(got, crafted) {
				t.Fatalf("on=%v: %v", on, err)
			}
		}
	}
}

// The limit is on what comes out, so a small object can't unpack past it.
func TestDecompressionIsBounded(t *testing.T) {
	ctx := context.Background()
	huge := bytes.Repeat([]byte("a"), 1<<20)
	c := &compressedBodies{BodyStore: &memBodies{objects: map[string][]byte{}}, compress: true}
	if err := c.Put(ctx, "k", huge); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, "k", 1024); err != ErrTooLarge {
		t.Fatalf("%v", err)
	}
}

// Compression goes first: encrypted bytes don't compress, so the other order
// would look fine and save nothing.
func TestCompressionUnderEncryption(t *testing.T) {
	ctx := context.Background()
	inner := &memBodies{objects: map[string][]byte{}}
	enc := &encryptedBodies{BodyStore: inner, keys: testBodyKeys(t, "v1:"+b64(1))}
	c := &compressedBodies{BodyStore: enc, compress: true}
	body := letter()
	if err := c.Put(ctx, "k", body); err != nil {
		t.Fatal(err)
	}
	stored := inner.objects["k"]
	if len(stored) >= len(body)/4 || bytes.Contains(stored, []byte("quarterly")) || bytes.HasPrefix(stored, bodyFrame) {
		t.Fatalf("stored %d of %d bytes, starting %q", len(stored), len(body), stored[:8])
	}
	got, err := c.Get(ctx, "k", int64(len(body)))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("%v", err)
	}
}

func compressedEngine(t *testing.T) (*Engine, Account, *memBodies) {
	t.Helper()
	e, a := isolatedTestEngine(t)
	inner := &memBodies{objects: map[string][]byte{}, identity: "mem:" + uuid.NewString()}
	e.Bodies = &compressedBodies{BodyStore: &encryptedBodies{BodyStore: inner, keys: testBodyKeys(t, "v1:"+b64(1))}}
	return e, a, inner
}

// Mail from before compression comes down in size, stays encrypted, and reads
// back the same, and running it again does nothing.
func TestCompressBodies(t *testing.T) {
	e, a, inner := compressedEngine(t)
	ctx := context.Background()
	// The noise goes after headers: as a whole message, random bytes made a
	// header line with a NUL in it often enough to fail the test now and then.
	photo := append([]byte("Subject: photo\r\nContent-Type: application/octet-stream\r\n\r\n"), noise(t, 4096)...)
	for _, body := range [][]byte{letter(), photo} {
		if _, err := e.Append(ctx, a.ID, "INBOX", body, nil, time.Now(), ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.CompressBodies(ctx, nil); err == nil {
		t.Fatal("ran with compression off")
	}
	e.Bodies.(*compressedBodies).compress = true
	r, err := e.CompressBodies(ctx, nil)
	if err != nil || r.Checked != 2 || r.Compressed != 1 || r.After >= r.Before/4 || len(r.Failed) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if again, err := e.CompressBodies(ctx, nil); err != nil || again.Compressed != 0 {
		t.Fatalf("%+v %v", again, err)
	}
	_, messages, err := e.Snapshot(ctx, a.ID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range messages {
		if _, err := e.Read(ctx, m); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(inner.objects[m.Body], []byte("quarterly")) {
			t.Fatal("a body lost its encryption")
		}
	}
	verified, err := e.Verify(ctx, 0, nil)
	if err != nil || !verified.OK() {
		t.Fatalf("%+v %v", verified, err)
	}
}

// A key rotation has to carry compressed mail over without unpacking it.
func TestRotationKeepsCompression(t *testing.T) {
	e, a, inner := compressedEngine(t)
	ctx := context.Background()
	e.Bodies.(*compressedBodies).compress = true
	res, err := e.Append(ctx, a.ID, "INBOX", letter(), nil, time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}
	_, messages, _ := e.Snapshot(ctx, a.ID, "INBOX")
	var m Message
	for _, x := range messages {
		if x.UID == res.UID {
			m = x
		}
	}
	before := len(inner.objects[m.Body])
	e.Bodies = &compressedBodies{BodyStore: &encryptedBodies{BodyStore: inner, keys: testBodyKeys(t, "v2:"+b64(2)+",v1:"+b64(1))}, compress: true}
	r, err := e.EncryptBodies(ctx, nil)
	if err != nil || r.Encrypted != 1 || len(r.Failed) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if after := len(inner.objects[m.Body]); after > before+16 {
		t.Fatalf("grew from %d to %d", before, after)
	}
	if _, err := e.Read(ctx, m); err != nil {
		t.Fatal(err)
	}
}

// Exports hold what's in the store, and a restore reads them back.
func TestRestoreReadsCompressedBackups(t *testing.T) {
	e, a, _ := compressedEngine(t)
	ctx := context.Background()
	e.Bodies.(*compressedBodies).compress = true
	uid, err := e.Append(ctx, a.ID, "INBOX", letter(), []string{`\Deleted`}, time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}
	r := newRestoreRig(t, e, a)
	r.snapshot(t)
	_, messages, _ := e.Snapshot(ctx, a.ID, "INBOX")
	stored, err := r.bodies.Get(ctx, messages[0].Body, int64(len(letter())))
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) >= len(letter())/4 || bytes.Contains(stored, []byte("quarterly")) {
		t.Fatalf("the export holds %d bytes", len(stored))
	}
	if _, err := e.Expunge(ctx, a.ID, "INBOX", []uint32{uid.UID}); err != nil {
		t.Fatal(err)
	}
	if got := r.restore(t, RestoreRequest{}); got.Restored != 1 || !got.Complete() {
		t.Fatalf("%+v", got)
	}
}
