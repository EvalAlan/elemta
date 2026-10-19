package mailbox

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

func TestTSPrefixQuery(t *testing.T) {
	for in, want := range map[string]string{
		"Invoice":           "invoice:*",
		"quarterly report":  "quarterly:* & report:*",
		"o'brien & co | !x": "o:* & brien:* & co:* & x:*",
		"!!!":               "",
		"Grüße aus München": "grüße:* & aus:* & münchen:*",
	} {
		if got := tsPrefixQuery(in); got != want {
			t.Errorf("tsPrefixQuery(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBodyText(t *testing.T) {
	raw := "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Hello <b>world</b> &amp; friends</p><script>secret()</script>\r\n" +
		"--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment\r\n\r\n%PDF-binary\r\n--b--\r\n"
	got := bodyText([]byte(raw))
	if !strings.Contains(got, "Hello") || !strings.Contains(got, "world") || !strings.Contains(got, "& friends") || strings.Contains(got, "secret") || strings.Contains(got, "PDF") {
		t.Errorf("bodyText = %q", got)
	}
}

// SEARCH must be answered by the index, without reading bodies.
func TestSearchUsesIndex(t *testing.T) {
	e, a := testEngine(t)
	ctx := context.Background()
	msgs := []string{
		"From: Ana Lima <ana@example.com>\r\nSubject: Quarterly invoices\r\nContent-Type: text/plain\r\n\r\nPlease pay the invoices by Friday.\r\n",
		"From: Bo <bo@example.com>\r\nTo: team@example.com\r\nSubject: Lunch\r\nContent-Type: text/html\r\n\r\n<p>Pizza at <b>noon</b></p>\r\n",
		"From: Cy <cy@example.com>\r\nSubject: Re: Lunch\r\n\r\nI'll bring dessert\r\n",
	}
	for _, raw := range msgs {
		if _, err := e.Append(ctx, a.ID, "INBOX", []byte(raw), nil, time.Now(), ""); err != nil {
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
	search := func(crit *imap.SearchCriteria) string {
		t.Helper()
		data, err := c.UIDSearch(crit, nil).Wait()
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprint(data.AllUIDs())
	}
	hdr := func(k, v string) []imap.SearchCriteriaHeaderField {
		return []imap.SearchCriteriaHeaderField{{Key: k, Value: v}}
	}
	for _, tc := range []struct {
		name string
		crit *imap.SearchCriteria
		want string
	}{
		{"from substring", &imap.SearchCriteria{Header: hdr("From", "LIMA")}, "[1]"},
		{"subject", &imap.SearchCriteria{Header: hdr("Subject", "lunch")}, "[2 3]"},
		{"to", &imap.SearchCriteria{Header: hdr("To", "team@")}, "[2]"},
		{"body word prefix", &imap.SearchCriteria{Body: []string{"invoice"}}, "[1]"},
		{"body in html", &imap.SearchCriteria{Body: []string{"noon"}}, "[2]"},
		{"text covers headers", &imap.SearchCriteria{Text: []string{"quarterly"}}, "[1]"},
		{"not", &imap.SearchCriteria{Not: []imap.SearchCriteria{{Header: hdr("Subject", "lunch")}}}, "[1]"},
		{"or", &imap.SearchCriteria{Or: [][2]imap.SearchCriteria{{{Body: []string{"dessert"}}, {Header: hdr("From", "ana")}}}}, "[1 3]"},
	} {
		if got := search(tc.crit); got != tc.want {
			t.Errorf("%s = %s, want %s", tc.name, got, tc.want)
		}
	}
	if n := counter.gets.Load(); n != 0 {
		t.Errorf("indexed searches read %d bodies", n)
	}
	// Mail without an index row is still found, by scanning.
	if _, err := e.DB.Exec(`DELETE FROM mailbox_summaries WHERE body IN (SELECT m.body FROM mailbox_messages m JOIN mailbox_folders f ON f.id=m.folder WHERE f.account=$1)`, a.ID); err != nil {
		t.Fatal(err)
	}
	if got := search(&imap.SearchCriteria{Body: []string{"dessert"}}); got != "[3]" {
		t.Errorf("unindexed body search = %s", got)
	}
	if got := search(&imap.SearchCriteria{Header: hdr("From", "lima")}); got != "[1]" {
		t.Errorf("unindexed header search = %s", got)
	}
}
