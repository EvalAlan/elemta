package webmail

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestUndoToken(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	u := undoMove{From: "Trash", To: "Projects/2026.Q4 — Ünïcode", UIDs: []uint32{1007, 1008}}
	tok := u.encode(now)
	got, ok := decodeUndo(tok, now.Add(30*time.Second))
	if !ok || got.From != u.From || got.To != u.To || got.UIDList() != "1007,1008" {
		t.Fatalf("round trip: %+v %v from %q", got, ok, tok)
	}
	if _, ok := decodeUndo(tok, now.Add(undoWindow+time.Second)); ok {
		t.Error("an undo past its window was accepted")
	}
	if _, ok := decodeUndo(tok, now.Add(-time.Minute)); ok {
		t.Error("an undo from the future was accepted")
	}
	for _, bad := range []string{"", "x", "1.2.3", "notatime.VHJhc2g.SU5CT1g.7", tok + ",x", strings.Replace(tok, ".", ".!!", 1)} {
		if _, ok := decodeUndo(bad, now); ok {
			t.Errorf("accepted %q", bad)
		}
	}
	many := undoMove{From: "Trash", To: "INBOX", UIDs: make([]uint32, maxUndoUIDs+1)}
	if many.encode(now) != "" {
		t.Error("a move too big to undo from the address was given a token")
	}
}

// Deleting from the inbox reports it with an Undo button that puts the
// message back; deleting in Trash is for good and offers none.
func TestUndoDelete(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	resp := h.post("/mail/action", url.Values{"csrf": {csrf}, "f": {"INBOX"}, "uid": {"7"}, "op": {"delete"}, "back": {"/mail?f=INBOX"}})
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(loc, "undo=") || h.store.moved[7] != "Trash" {
		t.Fatalf("delete: %d %q moved %v", resp.StatusCode, loc, h.store.moved)
	}
	_, page := h.get(loc)
	for _, want := range []string{`class="inline undo-form"`, `name="op" value="undo"`, `name="f" value="Trash"`, `name="uid" value="1007"`, `name="dest" value="INBOX"`, ">Undo</button>"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page after deleting lacks %s", want)
		}
	}

	resp = h.post("/mail/action", url.Values{"csrf": {csrf}, "f": {"Trash"}, "uid": {"1007"}, "op": {"undo"}, "dest": {"INBOX"}, "back": {"/mail?f=INBOX"}})
	loc = resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || h.store.moved[1007] != "INBOX" {
		t.Fatalf("undo: %d moved %v", resp.StatusCode, h.store.moved)
	}
	if !strings.Contains(loc, "n=undone") || strings.Contains(loc, "undo=") {
		t.Errorf("after undoing: %q, want the undone notice and no further undo", loc)
	}
	if _, page := h.get(loc); !strings.Contains(page, "Moved back.") || strings.Contains(page, "undo-form") {
		t.Error("the page after undoing doesn't say so, or offers to undo the undo")
	}

	// In Trash, delete is for good: nothing to undo.
	resp = h.post("/mail/action", url.Values{"csrf": {csrf}, "f": {"Trash"}, "uid": {"7"}, "op": {"delete"}, "back": {"/mail?f=Trash"}})
	if loc := resp.Header.Get("Location"); strings.Contains(loc, "undo=") || len(h.store.deleted) != 1 {
		t.Errorf("deleting in Trash: %q deleted %v, want it gone for good with no undo", loc, h.store.deleted)
	}
}

func TestUndoJunkAndMove(t *testing.T) {
	h := newHarness(t)
	csrf := h.login()
	for _, c := range []struct {
		form url.Values
		from string
	}{
		{url.Values{"op": {"junk"}}, "Junk"},
		{url.Values{"op": {"move"}, "dest": {"Sent"}}, "Sent"},
	} {
		c.form.Set("csrf", csrf)
		c.form.Set("f", "INBOX")
		c.form.Set("uid", "7")
		c.form.Set("back", "/mail?f=INBOX")
		resp := h.post("/mail/action", c.form)
		loc := resp.Header.Get("Location")
		u, err := url.Parse(loc)
		if err != nil {
			t.Fatal(err)
		}
		undo, ok := decodeUndo(u.Query().Get("undo"), time.Now())
		if !ok || undo.From != c.from || undo.To != "INBOX" || undo.UIDList() != "1007" {
			t.Errorf("%s: undo %+v %v from %q", c.form.Get("op"), undo, ok, loc)
		}
	}
}
