package webmail

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// withUndoSend runs a test with a one-second undo delay as the default.
func withUndoSend(t *testing.T) {
	t.Helper()
	defaultUndoSend = 1
	t.Cleanup(func() { defaultUndoSend = 0 })
}

func sendTestMessage(t *testing.T, h *harness, csrf string) *http.Response {
	t.Helper()
	return h.post("/compose", url.Values{"csrf": {csrf}, "to": {"priya@northwind.example"}, "subject": {"Kickoff"}, "body": {"See you Tuesday."}})
}

// waitSent waits for the fake submitter to get a message, or fails.
func waitSent(t *testing.T, h *harness, within time.Duration) {
	t.Helper()
	select {
	case <-h.sub.sent:
	case <-time.After(within):
		t.Fatal("the message wasn't sent")
	}
}

func notSent(t *testing.T, h *harness, within time.Duration) {
	t.Helper()
	select {
	case <-h.sub.sent:
		t.Fatal("the message was sent")
	case <-time.After(within):
	}
}

func expunged(h *harness, uid uint32) bool {
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	return slices.Contains(h.store.expunged, uid)
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Send waits out the delay with the message safe in Drafts, then sends it,
// files the sent copy and removes the draft.
func TestUndoSendWaitsThenSends(t *testing.T) {
	withUndoSend(t)
	h := newHarness(t)
	h.sub.sent = make(chan struct{}, 1)
	csrf := h.login()
	resp := sendTestMessage(t, h, csrf)
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(loc, "n=sending") {
		t.Fatalf("send: %d %q", resp.StatusCode, loc)
	}
	h.store.mu.Lock()
	drafts := len(h.store.appended[RoleDrafts])
	h.store.mu.Unlock()
	if drafts != 1 {
		t.Fatalf("the message wasn't saved to Drafts while it waits (%d drafts)", drafts)
	}
	_, page := h.get(loc)
	if !strings.Contains(page, "data-send-left=") || !strings.Contains(page, `action="/compose/undo"`) {
		t.Error("the page doesn't offer to undo the send")
	}
	notSent(t, h, 300*time.Millisecond)
	waitSent(t, h, 3*time.Second)
	eventually(t, "the safety draft wasn't removed after sending", func() bool { return expunged(h, 9001) })
	h.store.mu.Lock()
	sentCopies := len(h.store.appended[RoleSent])
	h.store.mu.Unlock()
	if sentCopies != 1 {
		t.Errorf("sent copies = %d", sentCopies)
	}
	// Once it's gone, the notice says so instead of offering Undo.
	if _, page := h.get(loc); strings.Contains(page, "undo-form") || !strings.Contains(page, "Message sent.") {
		t.Error("after sending, the page still offers Undo or doesn't say it was sent")
	}
}

func TestUndoSendStopsAndReopens(t *testing.T) {
	withUndoSend(t)
	h := newHarness(t)
	h.sub.sent = make(chan struct{}, 1)
	csrf := h.login()
	loc := sendTestMessage(t, h, csrf).Header.Get("Location")
	id := regexp.MustCompile(`send=([^&]+)`).FindStringSubmatch(loc)[1]
	resp := h.post("/compose/undo", url.Values{"csrf": {csrf}, "id": {id}})
	got := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(got, "/compose?") || !strings.Contains(got, "mode=draft") || !strings.Contains(got, "uid=9001") {
		t.Fatalf("undo: %d %q, want the draft opened", resp.StatusCode, got)
	}
	notSent(t, h, 1500*time.Millisecond)
	if expunged(h, 9001) {
		t.Error("the draft was removed after an undo")
	}
	// The editor opens the draft (which the fake store can't produce) with
	// this notice.
	if _, page := h.get("/compose?n=send-undone"); !strings.Contains(page, "Not sent.") {
		t.Error("the editor doesn't say the message wasn't sent")
	}
	// A second undo, or one from another session, finds nothing.
	if loc := h.post("/compose/undo", url.Values{"csrf": {csrf}, "id": {id}}).Header.Get("Location"); !strings.Contains(loc, "send-too-late") {
		t.Errorf("second undo: %q", loc)
	}
}

func TestUndoSendTooLate(t *testing.T) {
	withUndoSend(t)
	h := newHarness(t)
	h.sub.sent = make(chan struct{}, 1)
	csrf := h.login()
	loc := sendTestMessage(t, h, csrf).Header.Get("Location")
	id := regexp.MustCompile(`send=([^&]+)`).FindStringSubmatch(loc)[1]
	waitSent(t, h, 3*time.Second)
	if loc := h.post("/compose/undo", url.Values{"csrf": {csrf}, "id": {id}}).Header.Get("Location"); !strings.Contains(loc, "send-too-late") {
		t.Errorf("undo after sending: %q", loc)
	}
}

// A delayed send that fails leaves the message in Drafts and says so on the
// next page, once.
func TestUndoSendFailureKeepsTheDraft(t *testing.T) {
	withUndoSend(t)
	h := newHarness(t)
	h.sub.sent = make(chan struct{}, 1)
	h.sub.err = errors.New("connection refused")
	csrf := h.login()
	sendTestMessage(t, h, csrf)
	waitSent(t, h, 3*time.Second)
	var page string
	eventually(t, "the failure wasn't reported", func() bool {
		_, page = h.get("/mail?f=INBOX")
		return strings.Contains(page, "be sent. It")
	})
	if !strings.Contains(page, "saved in Drafts") || expunged(h, 9001) {
		t.Error("a failed send didn't keep its draft")
	}
	if _, page := h.get("/mail?f=INBOX"); strings.Contains(page, "be sent. It") {
		t.Error("the failure was reported twice")
	}
}

// A shutdown sends what is waiting rather than leaving it.
func TestFlushPendingSends(t *testing.T) {
	defaultUndoSend = 30
	t.Cleanup(func() { defaultUndoSend = 0 })
	h := newHarness(t)
	h.sub.sent = make(chan struct{}, 1)
	csrf := h.login()
	sendTestMessage(t, h, csrf)
	notSent(t, h, 200*time.Millisecond)
	h.server.FlushPendingSends(context.Background())
	waitSent(t, h, time.Second)
}

func TestUndoSendSetting(t *testing.T) {
	for v, want := range map[string]int{"": defaultUndoSend, "0": 0, "5": 5, "30": 30, "7": defaultUndoSend, "x": defaultUndoSend} {
		if got := (Settings{UndoSend: v}).UndoSendSeconds(); got != want {
			t.Errorf("UndoSend %q = %d, want %d", v, got, want)
		}
	}
	withUndoSend(t)
	h := newHarness(t)
	h.sub.sent = make(chan struct{}, 1)
	csrf := h.login()
	h.post("/settings", url.Values{"csrf": {csrf}, "undo_send": {"0"}, "week_start": {"0"}, "clock": {"24"}, "page_size": {"50"}})
	if _, page := h.get("/settings"); !strings.Contains(page, `<option value="0" selected>`) {
		t.Error("settings don't show undo send off")
	}
	if loc := sendTestMessage(t, h, csrf).Header.Get("Location"); !strings.Contains(loc, "n=sent") {
		t.Errorf("with undo send off: %q, want sent at once", loc)
	}
	waitSent(t, h, time.Second)
}
