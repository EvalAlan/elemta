package sieve

import (
	"context"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/EvalAlan/elemta/internal/sievefork/interp"
)

// A script shaped like the webmail's: out-of-office within a date range,
// with list guards, then rules using regex, fileinto :copy :create and flags.
const webmailScript = `require ["vacation", "date", "relational", "regex", "fileinto", "mailbox", "copy", "imap4flags"];
if allof (currentdate :value "ge" "date" "2026-10-01", currentdate :value "le" "date" "2026-10-31",
          not anyof (exists "list-id", header :contains "precedence" ["bulk", "list", "junk"], exists "auto-submitted")) {
  vacation :days 3 :subject "Away" :addresses ["ana@example.com", "a.lima@example.com"] "Back on Monday.";
}
# Invoices
if header :regex "subject" "^(invoice|bill) #[0-9]+$" {
  addflag "\\Flagged";
  fileinto :copy :create "Finance/Invoices";
}
`

func run(t *testing.T, script string, now time.Time, headers map[string]string) []interp.AppliedAction {
	t.Helper()
	s, err := Load(strings.NewReader(script), DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	h := textproto.MIMEHeader{}
	for k, v := range headers {
		h.Set(k, v)
	}
	d := NewRuntimeData(s, interp.DummyPolicy{}, interp.EnvelopeStatic{From: "bo@example.com", To: "ana@example.com"}, interp.MessageStatic{Header: h, Size: 100})
	d.Now = func() time.Time { return now }
	d.Location = time.UTC
	if err := s.Execute(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	return d.AppliedActions
}

func TestWebmailScript(t *testing.T) {
	inRange := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	acts := run(t, webmailScript, inRange, map[string]string{"Subject": "Invoice #42"})
	var vac *interp.ActionVacation
	var file *interp.ActionFileInto
	keep := false
	for _, a := range acts {
		switch a := a.(type) {
		case interp.ActionVacation:
			vac = &a
		case interp.ActionFileInto:
			file = &a
		case interp.ActionKeep:
			keep = true
		}
	}
	if vac == nil || vac.Period != 72*time.Hour || vac.Subject != "Away" || vac.Reason != "Back on Monday." || len(vac.Addresses) != 2 {
		t.Fatalf("vacation = %+v", vac)
	}
	if file == nil || file.Mailbox != "Finance/Invoices" || !file.Copy || !file.Create || !strings.Contains(strings.Join(file.Flags, " "), `\Flagged`) {
		t.Fatalf("fileinto = %+v", file)
	}
	if !keep {
		t.Error(":copy should keep the implicit keep")
	}
	// Outside the date range, and for list mail, there is no reply.
	for _, tc := range []struct {
		now time.Time
		h   map[string]string
	}{
		{time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), map[string]string{"Subject": "x"}},
		{inRange, map[string]string{"Subject": "x", "List-Id": "<team.example.com>"}},
		{inRange, map[string]string{"Subject": "x", "Auto-Submitted": "auto-replied"}},
	} {
		for _, a := range run(t, webmailScript, tc.now, tc.h) {
			if _, ok := a.(interp.ActionVacation); ok {
				t.Errorf("vacation fired for %v %v", tc.now, tc.h)
			}
		}
	}
	// The regex must match the whole subject.
	for _, a := range run(t, webmailScript, inRange, map[string]string{"Subject": "Re: Invoice #42"}) {
		if _, ok := a.(interp.ActionFileInto); ok {
			t.Error("regex matched a reply")
		}
	}
}

func TestExtensionsNeedRequire(t *testing.T) {
	for _, script := range []string{
		`vacation "x";`,
		`if currentdate :is "year" "2026" { keep; }`,
		`if header :regex "subject" "x" { keep; }`,
		`require "fileinto"; fileinto :create "x";`,
	} {
		if _, err := Load(strings.NewReader(script), DefaultOptions()); err == nil {
			t.Errorf("accepted without require: %s", script)
		}
	}
}

func TestDateParts(t *testing.T) {
	when := time.Date(2026, 10, 18, 7, 5, 9, 0, time.UTC)
	for part, want := range map[string]string{"year": "2026", "month": "10", "day": "18", "date": "2026-10-18", "time": "07:05:09", "weekday": "0", "zone": "+0000", "julian": "61331"} {
		script := `require ["date"]; if currentdate :is "` + part + `" "` + want + `" { discard; }`
		found := false
		for _, a := range run(t, script, when, nil) {
			if _, ok := a.(interp.ActionDiscard); ok {
				found = true
			}
		}
		if !found {
			t.Errorf("date-part %s != %s", part, want)
		}
	}
	// The date test reads a header, in the zone requested.
	script := `require ["date"]; if date :zone "+0200" "date" "hour" "11" { discard; }`
	found := false
	for _, a := range run(t, script, when, map[string]string{"Date": "Sun, 18 Oct 2026 09:00:00 +0000"}) {
		if _, ok := a.(interp.ActionDiscard); ok {
			found = true
		}
	}
	if !found {
		t.Error("date :zone didn't convert")
	}
}
