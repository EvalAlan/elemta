package mailbox

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/EvalAlan/elemta/internal/sievefork/interp"
	gomessage "github.com/emersion/go-message"
	gomail "github.com/emersion/go-message/mail"
)

// vacation :mime gives the reply as a MIME entity. Its Content-* headers
// belong in the reply's header; they used to land in the body as text.
func TestVacationMimeReasonIsAnEntity(t *testing.T) {
	s := &Service{}
	s.cfg.Sieve.Hostname = "mailbox.test"
	var orig gomail.Header
	orig.SetSubject("Lunch?")
	d := delivery{rcpt: "dana@example.com", from: "pat@remote.example"}

	for _, tc := range []struct {
		name, reason, wantType, wantBody string
	}{
		{"html entity", "Content-Type: text/html; charset=utf-8\n\n<p>Away until <b>Monday</b>.</p>\n",
			"text/html", "<p>Away until <b>Monday</b>.</p>"},
		{"no header section, sent as text", "Away until Monday.\n", "text/plain", "Away until Monday."},
		{"header-like first line, sent as text", "Note: back Monday\n\nThanks\n", "text/plain", "Note: back Monday\r\n\r\nThanks"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := s.vacationReply(d, orig, interp.ActionVacation{Mime: true, Reason: tc.reason})
			if err != nil {
				t.Fatal(err)
			}
			e, err := gomessage.Read(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("reply doesn't parse: %v\n%s", err, raw)
			}
			if typ, _, _ := e.Header.ContentType(); typ != tc.wantType {
				t.Errorf("Content-Type %q, want %q\n%s", typ, tc.wantType, raw)
			}
			if got := e.Header.Get("To"); !strings.Contains(got, "pat@remote.example") {
				t.Errorf("To = %q", got)
			}
			body, _ := io.ReadAll(e.Body)
			if strings.TrimSpace(string(body)) != tc.wantBody {
				t.Errorf("body %q, want %q", body, tc.wantBody)
			}
		})
	}
}
