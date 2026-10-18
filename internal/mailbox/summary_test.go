package mailbox

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

type countingBodies struct {
	BodyStore
	gets atomic.Int64
}

func (c *countingBodies) Get(ctx context.Context, key string, size int64) ([]byte, error) {
	c.gets.Add(1)
	return c.BodyStore.Get(ctx, key, size)
}

func TestBaseSubject(t *testing.T) {
	for in, want := range map[string]string{
		"Hello":                          "hello",
		"Re: Hello":                      "hello",
		"RE: re: Fwd: Hello":             "hello",
		"Re[2]: Hello":                   "hello",
		"[list] Re: Hello (fwd)":         "hello",
		"[Fwd: Hello]":                   "hello",
		"  Many   spaces  ":              "many spaces",
		"[only a tag]":                   "[only a tag]",
		"Reply all: not a marker":        "reply all: not a marker",
		"Fw: [team] Re: Quarterly (fwd)": "quarterly",
	} {
		if got := baseSubject(in); got != want {
			t.Errorf("baseSubject(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSummarize(t *testing.T) {
	raw := []byte("From: Ana Lima <Ana@Example.com>\r\nTo: bo@example.com\r\nSubject: Re: Plans\r\nDate: Mon, 05 Oct 2026 09:00:00 +0000\r\n" +
		"Message-ID: <m2@example.com>\r\nIn-Reply-To: <m1@example.com>\r\n\r\nbody\r\n")
	s := summarize(raw)
	if s.BaseSubject != "plans" || s.From != "ana@example.com" || s.DisplayFrom != "ana lima" || s.To != "bo@example.com" {
		t.Errorf("summary = %+v", s)
	}
	if s.MessageID != "m2@example.com" || len(s.References) != 1 || s.References[0] != "m1@example.com" {
		t.Errorf("ids = %q %q", s.MessageID, s.References)
	}
	if !strings.HasSuffix(string(s.Header), "\r\n\r\n") || strings.Contains(string(s.Header), "body") {
		t.Errorf("header block = %q", s.Header)
	}
	data, err := encodeSummary(s)
	if err != nil {
		t.Fatal(err)
	}
	back, err := decodeSummary(data)
	if err != nil || back.Envelope.Subject != "Re: Plans" || back.Structure == nil {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
}

// A message list must not read bodies: envelope, structure and header
// fields come from the stored summary.
func TestFetchListFromSummaries(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		raw := []byte("From: s@example.com\r\nSubject: list " + string(rune('a'+i)) + "\r\nReferences: <r@example.com>\r\n\r\nbody\r\n")
		if _, err := e.Append(ctx, a.ID, "INBOX", raw, nil, time.Now(), ""); err != nil {
			t.Fatal(err)
		}
	}
	counter := &countingBodies{BodyStore: e.Bodies}
	e.Bodies = counter
	_, addr, _ := startTestService(t, e, a)
	c, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Login(a.Address, "testpass").Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	refs := &imap.FetchItemBodySection{Specifier: imap.PartSpecifierHeader, HeaderFields: []string{"References"}, Peek: true}
	msgs, err := c.Fetch(imap.SeqSetNum(1, 2, 3, 4, 5), &imap.FetchOptions{
		Envelope: true, BodyStructure: &imap.FetchItemBodyStructure{}, Flags: true, RFC822Size: true, BodySection: []*imap.FetchItemBodySection{refs},
	}).Collect()
	if err != nil || len(msgs) != 5 {
		t.Fatalf("fetch = %d, %v", len(msgs), err)
	}
	if msgs[2].Envelope.Subject != "list c" || !strings.Contains(string(msgs[2].FindBodySection(refs)), "<r@example.com>") || msgs[2].BodyStructure == nil {
		t.Fatalf("fetched %+v", msgs[2])
	}
	if n := counter.gets.Load(); n != 0 {
		t.Fatalf("message list read %d bodies", n)
	}
	// A full body fetch still reads the body.
	if _, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{Peek: true}}}).Collect(); err != nil {
		t.Fatal(err)
	}
	if counter.gets.Load() != 1 {
		t.Fatalf("body reads = %d", counter.gets.Load())
	}
}

func TestSummaryBackfill(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	res, err := e.Append(ctx, a.ID, "INBOX", []byte("Subject: old mail\r\n\r\nx\r\n"), nil, time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate mail stored before summaries existed.
	if _, err := e.DB.Exec(`DELETE FROM mailbox_summaries WHERE body IN (SELECT body FROM mailbox_messages m JOIN mailbox_folders f ON f.id=m.folder WHERE f.account=$1)`, a.ID); err != nil {
		t.Fatal(err)
	}
	_, msgs, err := e.Snapshot(ctx, a.ID, "INBOX")
	if err != nil || len(msgs) != 1 || msgs[0].UID != res.UID {
		t.Fatal(msgs, err)
	}
	if got, _ := e.Summaries(ctx, msgs); len(got) != 0 {
		t.Fatal("summary not removed")
	}
	// The test database is shared with other tests, whose body files are
	// gone; backfill reports those, so keep going until ours is done.
	for i := 0; i < 100; i++ {
		_, _ = e.Backfill(ctx, 1000)
		if got, _ := e.Summaries(ctx, msgs); got[msgs[0].Body] != nil {
			break
		}
	}
	got, err := e.Summaries(ctx, msgs)
	if err != nil || got[msgs[0].Body] == nil || got[msgs[0].Body].Envelope.Subject != "old mail" {
		t.Fatalf("after backfill = %v, %v", got, err)
	}
}

func TestChangesReplay(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	add := func(s string) uint32 {
		r, err := e.Append(ctx, a.ID, "INBOX", []byte("Subject: "+s+"\r\n\r\nx\r\n"), nil, time.Now(), "")
		if err != nil {
			t.Fatal(err)
		}
		return r.UID
	}
	u1, u2 := add("one"), add("two")
	f, _, err := e.Snapshot(ctx, a.ID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	u3 := add("three")
	if err := e.MutateFlags(ctx, a.ID, "INBOX", []uint32{u1}, []string{"\\Flagged"}, 1); err != nil {
		t.Fatal(err)
	}
	if err := e.MutateFlags(ctx, a.ID, "INBOX", []uint32{u2}, []string{"\\Deleted"}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Expunge(ctx, a.ID, "INBOX", []uint32{u2}); err != nil {
		t.Fatal(err)
	}
	ch, err := e.Changes(ctx, a.ID, f.ID, f.ModSeq)
	if err != nil || !ch.Complete {
		t.Fatalf("changes = %+v, %v", ch, err)
	}
	changed := map[uint32]Message{}
	for _, m := range ch.Changed {
		changed[m.UID] = m
	}
	if _, ok := changed[u3]; !ok || !hasFlag(changed[u1].Flags, "\\flagged") || len(ch.Gone) != 1 || ch.Gone[0] != u2 {
		t.Fatalf("changes = %+v", ch)
	}
	if ch, _ := e.Changes(ctx, a.ID, f.ID, ch.Folder.ModSeq); len(ch.Changed)+len(ch.Gone) != 0 || !ch.Complete {
		t.Fatalf("no-op changes = %+v", ch)
	}
	// Once the journal is trimmed past a session's MODSEQ, it must take a
	// full snapshot instead of trusting a partial answer.
	if _, err := e.DB.Exec(`UPDATE mailbox_changes SET created=now()-interval '2 days' WHERE folder=$1`, f.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.CompactChanges(ctx, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if ch, err := e.Changes(ctx, a.ID, f.ID, f.ModSeq); err != nil || ch.Complete {
		t.Fatalf("after compaction = %+v, %v", ch, err)
	}
}

func TestSelectedIdx(t *testing.T) {
	s := &imapSession{}
	for _, u := range []uint32{2, 5, 7, 9, 12} {
		s.view = append(s.view, Message{UID: u})
	}
	var uids imap.UIDSet
	uids.AddRange(5, 9)
	uids.AddNum(12)
	uids.AddNum(100)
	if got := s.selected(uids); len(got) != 4 || got[0] != 5 || got[3] != 12 {
		t.Errorf("uid set = %v", got)
	}
	var star imap.UIDSet
	star.AddRange(10, 0) // 10:* includes the highest UID
	if got := s.selected(star); len(got) != 1 || got[0] != 12 {
		t.Errorf("10:* = %v", got)
	}
	var seq imap.SeqSet
	seq.AddRange(2, 3)
	seq.AddRange(5, 0)
	if got := s.selected(seq); len(got) != 3 || got[0] != 5 || got[2] != 12 {
		t.Errorf("seq set = %v", got)
	}
}
