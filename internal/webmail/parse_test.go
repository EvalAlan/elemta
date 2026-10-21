package webmail

import (
	"strings"
	"testing"
)

const multipartMessage = "From: \"Priya Shah\" <priya@northwind.example>\r\n" +
	"To: Dana Okafor <dana@example.com>, marcus@example.com\r\n" +
	"Cc: legal@northwind.example\r\n" +
	"Subject: =?UTF-8?Q?Signed_MSA_=E2=9C=93?=\r\n" +
	"Date: Mon, 19 Oct 2026 09:42:00 +0000\r\n" +
	"Message-Id: <msa@northwind.example>\r\n" +
	"Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=northwind.example; dkim=pass header.d=northwind.example; dmarc=pass\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/mixed; boundary=outer\r\n" +
	"\r\n" +
	"--outer\r\n" +
	"Content-Type: multipart/related; boundary=rel\r\n" +
	"\r\n" +
	"--rel\r\n" +
	"Content-Type: multipart/alternative; boundary=alt\r\n" +
	"\r\n" +
	"--alt\r\n" +
	"Content-Type: text/plain; charset=iso-8859-1\r\n" +
	"Content-Transfer-Encoding: quoted-printable\r\n" +
	"\r\n" +
	"Caf=E9 at ten.\r\n" +
	"--alt\r\n" +
	"Content-Type: text/html; charset=utf-8\r\n" +
	"\r\n" +
	"<p>Café at ten.</p><img src=\"cid:logo@nw\">\r\n" +
	"--alt--\r\n" +
	"--rel\r\n" +
	"Content-Type: image/png; name=logo.png\r\n" +
	"Content-Id: <logo@nw>\r\n" +
	"Content-Transfer-Encoding: base64\r\n" +
	"\r\n" +
	"iVBORw0KGgo=\r\n" +
	"--rel--\r\n" +
	"--outer\r\n" +
	"Content-Type: application/pdf\r\n" +
	"Content-Disposition: attachment; filename=\"MSA countersigned.pdf\"\r\n" +
	"Content-Transfer-Encoding: base64\r\n" +
	"\r\n" +
	"JVBERi0xLjQK\r\n" +
	"--outer--\r\n"

func TestParseMessage(t *testing.T) {
	m, err := parseMessage([]byte(multipartMessage))
	if err != nil {
		t.Fatal(err)
	}
	if m.Subject != "Signed MSA ✓" {
		t.Errorf("subject = %q", m.Subject)
	}
	if len(m.From) != 1 || m.From[0].Name != "Priya Shah" || m.From[0].Email != "priya@northwind.example" {
		t.Errorf("from = %+v", m.From)
	}
	if len(m.To) != 2 || len(m.Cc) != 1 {
		t.Errorf("to/cc = %+v / %+v", m.To, m.Cc)
	}
	if strings.TrimSpace(m.Text) != "Café at ten." {
		t.Errorf("latin-1 text not decoded: %q", m.Text)
	}
	if !strings.Contains(m.HTML, "cid:logo@nw") {
		t.Errorf("html = %q", m.HTML)
	}
	if m.MessageID != "<msa@northwind.example>" {
		t.Errorf("message id = %q", m.MessageID)
	}

	att := m.Attachments()
	if len(att) != 1 || att[0].Filename != "MSA countersigned.pdf" || att[0].ContentType != "application/pdf" {
		t.Fatalf("attachments = %+v (inline cid image must be left out)", att)
	}

	part, body, err := findPart([]byte(multipartMessage), att[0].Index, "")
	if err != nil {
		t.Fatal(err)
	}
	if part.Filename != "MSA countersigned.pdf" || !strings.HasPrefix(string(body), "%PDF") {
		t.Errorf("findPart by index = %+v %q", part, body)
	}
	part, body, err = findPart([]byte(multipartMessage), 0, "logo@nw")
	if err != nil {
		t.Fatal(err)
	}
	if part.ContentType != "image/png" || len(body) == 0 {
		t.Errorf("findPart by cid = %+v", part)
	}
	if _, _, err := findPart([]byte(multipartMessage), 99, ""); err != ErrNotFound {
		t.Errorf("missing part err = %v", err)
	}
}

func TestParseAuthResults(t *testing.T) {
	m, _ := parseMessage([]byte(multipartMessage))
	got := parseAuthResults(m.AuthResults)
	if len(got) != 3 {
		t.Fatalf("checks = %+v", got)
	}
	for _, c := range got {
		if !c.Pass {
			t.Errorf("%s = %s, want pass", c.Method, c.Result)
		}
	}
	got = parseAuthResults("mx; dkim=fail header.d=x; dkim=pass header.d=y")
	if len(got) != 1 || got[0].Pass {
		t.Errorf("first result per method should win: %+v", got)
	}
}

func TestParsePlainMessageWithBadAddress(t *testing.T) {
	raw := "From: not an address\r\nSubject: hi\r\n\r\nplain body\r\n"
	m, err := parseMessage([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.From) != 1 || m.From[0].Name != "not an address" {
		t.Errorf("unparsable From should be kept raw: %+v", m.From)
	}
	if strings.TrimSpace(m.Text) != "plain body" {
		t.Errorf("text = %q", m.Text)
	}
}

// 8-bit headers and undeclared text in Windows-1252, common in older mail,
// display as text instead of making the page invalid UTF-8.
func TestLegacy8BitTextIsDecoded(t *testing.T) {
	raw := "From: Jos\xe9 <jose@example.com>\r\nSubject: Price: 5\xa2 per caf\xe9\r\nDate: Mon, 20 Oct 2026 10:00:00 +0000\r\n\r\nNa\xefve body\r\n"
	msg, err := parseMessage([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Subject != "Price: 5¢ per café" || len(msg.From) != 1 || msg.From[0].Name != "José" {
		t.Errorf("subject %q, from %+v", msg.Subject, msg.From)
	}
	if !strings.Contains(msg.Text, "Naïve body") {
		t.Errorf("text %q", msg.Text)
	}
	if got := legacyText("already UTF-8: café"); got != "already UTF-8: café" {
		t.Errorf("valid UTF-8 changed: %q", got)
	}
}
