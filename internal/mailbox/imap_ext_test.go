package mailbox

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/imapfork/imapserver"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

func render(ts []imapserver.Thread) string {
	out := ""
	for _, t := range ts {
		out += "(" + fmt.Sprint(t.Num)
		for _, c := range t.Children {
			out += " " + render([]imapserver.Thread{c})
		}
		out += ")"
	}
	return out
}

func item(num uint32, id, subject string, day int, refs ...string) *threadItem {
	return &threadItem{num: num, seq: int(num), id: id, refs: refs, subject: baseSubject(subject), reply: hasReplyMarker(subject),
		sent: time.Date(2026, 10, day, 9, 0, 0, 0, time.UTC)}
}

func TestThreadReferencesAlgorithm(t *testing.T) {
	items := []*threadItem{
		item(1, "a", "Plans", 1),
		item(2, "b", "Re: Plans", 2, "a"),
		item(3, "c", "Re: Plans", 3, "a", "b"),
		item(4, "d", "Re: Plans", 4, "a"),  // second reply to the first message
		item(5, "e", "Lunch", 2),           // unrelated
		item(6, "f", "Re: Lunch", 5, "zz"), // replies to a message we don't have; joined by subject
		item(7, "g", "Budget", 6, "g"),     // references itself: no loop
		item(8, "h", "Re: Old thread", 7, "missing-1", "missing-2"),
	}
	got := render(threadReferences(items))
	// 6's missing parent is pruned, then the subject pass puts the reply
	// under the original "Lunch".
	want := "(1 (2 (3)) (4))(5 (6))(7)(8)" // render separates siblings with a space
	if got != want {
		t.Errorf("threads = %s, want %s", got, want)
	}
}

func TestThreadOrderedSubject(t *testing.T) {
	items := []*threadItem{item(1, "", "Plans", 1), item(2, "", "Lunch", 2), item(3, "", "Re: Plans", 3)}
	if got := render(threadOrderedSubject(items)); got != "(1 (3))(2)" {
		t.Errorf("ordered subject = %s", got)
	}
}

func TestReplyMarker(t *testing.T) {
	for s, want := range map[string]bool{"Re: x": true, "[list] Fwd: x": true, "x (fwd)": true, "x": false, "[list] x": false, "Regarding x": false} {
		if hasReplyMarker(s) != want {
			t.Errorf("hasReplyMarker(%q) != %v", s, want)
		}
	}
}

func TestSortThreadQuotaIDProtocol(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	msgs := []string{
		"From: Zed <zed@example.com>\r\nDate: Mon, 05 Oct 2026 09:00:00 +0000\r\nSubject: banana\r\nMessage-ID: <1@x>\r\n\r\nx\r\n",
		"From: Amy <amy@example.com>\r\nDate: Wed, 07 Oct 2026 09:00:00 +0000\r\nSubject: Re: apple\r\nMessage-ID: <2@x>\r\nReferences: <3@x>\r\n\r\nxxxxxxxxxx\r\n",
		"From: Bob <bob@example.com>\r\nDate: Tue, 06 Oct 2026 09:00:00 +0000\r\nSubject: apple\r\nMessage-ID: <3@x>\r\n\r\nxxxxx\r\n",
	}
	for _, raw := range msgs {
		if _, err := e.Append(ctx, a.ID, "INBOX", []byte(raw), nil, time.Now(), ""); err != nil {
			t.Fatal(err)
		}
	}
	_, addr, _ := startTestService(t, e, a)
	c, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	id, err := c.ID(&imap.IDData{Name: "test"}).Wait()
	if err != nil || id.Name != "Elemta" {
		t.Fatalf("ID = %+v, %v", id, err)
	}
	if err := c.Login(a.Address, "testpass").Wait(); err != nil {
		t.Fatal(err)
	}
	// Sign-in refreshes the quota from the directory, so set it after.
	if _, err := e.DB.Exec(`UPDATE mailbox_accounts SET quota_bytes=10485760 WHERE id=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	caps, err := c.Capability().Wait()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []imap.Cap{"SORT", "THREAD=REFERENCES", "QUOTA", "ID"} {
		if !caps.Has(want) {
			t.Errorf("capability %s missing: %v", want, caps)
		}
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	all := &imap.SearchCriteria{}
	check := func(key imapclient.SortKey, reverse bool, want string) {
		t.Helper()
		got, err := c.UIDSort(&imapclient.SortOptions{SearchCriteria: all, SortCriteria: []imapclient.SortCriterion{{Key: key, Reverse: reverse}}}).Wait()
		if err != nil || fmt.Sprint(got) != want {
			t.Errorf("SORT %s reverse=%v = %v, %v; want %s", key, reverse, got, err, want)
		}
	}
	check(imapclient.SortKeyDate, false, "[1 3 2]")
	check(imapclient.SortKeyDate, true, "[2 3 1]")
	check(imapclient.SortKeySubject, false, "[2 3 1]") // apple (by mailbox order), banana
	check(imapclient.SortKeyFrom, false, "[2 3 1]")
	check(imapclient.SortKeySize, true, "[2 3 1]")
	check(imapclient.SortKeyArrival, false, "[1 2 3]")
	threads, err := c.UIDThread(&imapclient.ThreadOptions{Algorithm: imap.ThreadReferences, SearchCriteria: all}).Wait()
	if err != nil || len(threads) != 2 {
		t.Fatalf("THREAD = %+v, %v", threads, err)
	}
	roots, err := c.GetQuotaRoot("INBOX").Wait()
	if err != nil || len(roots) != 1 {
		t.Fatalf("GETQUOTAROOT = %+v, %v", roots, err)
	}
	if st := roots[0].Resources[imap.QuotaResourceStorage]; st.Limit != 10240 || st.Usage < 1 {
		t.Errorf("storage quota = %+v", st)
	}
}
