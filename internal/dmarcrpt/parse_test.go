package dmarcrpt

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var parseNow = time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

func parseRecord(ip, count string) string {
	return `<record><row><source_ip>` + ip + `</source_ip><count>` + count + `</count><policy_evaluated><disposition>reject</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row>` +
		`<identifiers><header_from>Example.COM</header_from></identifiers><auth_results><dkim><domain>example.com</domain><result>pass</result></dkim><spf><domain>esp.example</domain><result>pass</result></spf></auth_results></record>`
}

func parseDoc(records string) string {
	begin := parseNow.Add(-48 * time.Hour).Unix()
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><feedback><version>1.0</version><report_metadata><org_name>Receiver</org_name><email>reports@receiver.example</email><report_id>r-1</report_id><date_range><begin>%d</begin><end>%d</end></date_range></report_metadata><policy_published><domain>example.com</domain><p>reject</p><pct>100</pct></policy_published>%s</feedback>`, begin, begin+86399, records)
}

func gzipped(t testing.TB, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func zipped(t testing.TB, files ...[]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for i, data := range files {
		f, err := w.Create(fmt.Sprintf("report-%d.xml", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestParseAttachment(t *testing.T) {
	doc := parseDoc(parseRecord("::ffff:192.0.2.1", "42") + parseRecord("2001:DB8::1", "1"))
	for name, data := range map[string][]byte{
		"xml":       []byte(doc),
		"bom":       []byte("\xef\xbb\xbf" + doc),
		"gzip":      gzipped(t, []byte(doc)),
		"zip":       zipped(t, []byte(doc)),
		"latin":     []byte(strings.Replace(strings.Replace(doc, "UTF-8", "ISO-8859-1", 1), "Receiver", "R\xe9ception", 1)),
		"namespace": []byte(strings.Replace(doc, "<feedback>", `<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">`, 1)),
	} {
		f, err := ParseAttachment(data, parseNow)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if f.PolicyPublished.Domain != "example.com" || len(f.Records) != 2 {
			t.Fatalf("%s: %+v", name, f)
		}
		r := f.Records[0]
		if r.Row.SourceIP != "192.0.2.1" || r.Row.Count != 42 || r.Identifiers.HeaderFrom != "example.com" || r.Row.PolicyEvaluated.Disposition != "reject" || r.Row.PolicyEvaluated.DKIM != "pass" {
			t.Fatalf("%s: %+v", name, r)
		}
		if f.Records[1].Row.SourceIP != "2001:db8::1" {
			t.Fatalf("%s: %+v", name, f.Records[1])
		}
	}
}

// What this server sends, it can read.
func TestParseOwnReport(t *testing.T) {
	day := parseNow.Add(-48 * time.Hour).Format("2006-01-02")
	f, err := buildReport(day, "example.com", &dayCounts{Policy: Policy{Domain: "example.com", P: "quarantine", Pct: 100}}, "Elemta", "postmaster@example.net", "mail.example.net")
	if err != nil {
		t.Fatal(err)
	}
	data, err := gzipXML(f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAttachment(data, parseNow)
	if err != nil || got.ReportMetadata.ReportID != f.ReportMetadata.ReportID || got.PolicyPublished.P != "quarantine" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestParseRefuses(t *testing.T) {
	good := parseDoc(parseRecord("192.0.2.1", "1"))
	bomb := bytes.Repeat([]byte(" "), MaxReportExpanded+1)
	for name, data := range map[string][]byte{
		"dtd":          []byte(strings.Replace(good, "<feedback>", `<!DOCTYPE feedback [<!ENTITY a "aaaa">]><feedback>`, 1)),
		"entity":       []byte(strings.Replace(good, "Receiver", "&a;", 1)),
		"gzip bomb":    gzipped(t, bomb),
		"zip bomb":     zipped(t, bomb),
		"two in zip":   zipped(t, []byte(good), []byte(good)),
		"oversized":    make([]byte, MaxReportCompressed+1),
		"address":      []byte(parseDoc(parseRecord("not-an-ip", "1"))),
		"zone":         []byte(parseDoc(parseRecord("fe80::1%eth0", "1"))),
		"zero count":   []byte(parseDoc(parseRecord("192.0.2.1", "0"))),
		"huge count":   []byte(parseDoc(parseRecord("192.0.2.1", "9999999999"))),
		"policy":       []byte(strings.Replace(good, "<domain>example.com</domain><p>", "<domain>not a domain</domain><p>", 1)),
		"from":         []byte(strings.Replace(good, "Example.COM", "&lt;b&gt;x", 1)),
		"no id":        []byte(strings.Replace(good, "r-1", "", 1)),
		"truncated":    []byte(good[:len(good)-20]),
		"two roots":    []byte(good + "<feedback></feedback>"),
		"many records": []byte(parseDoc(strings.Repeat("<record/>", MaxReportRecords+1))),
		"bad charset":  []byte(strings.Replace(good, "UTF-8", "x-unknown", 1)),
	} {
		if _, err := ParseAttachment(data, parseNow); !errors.Is(err, ErrBadReport) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseAttachment([]byte(good), parseNow.AddDate(-1, 0, 0)); !errors.Is(err, ErrBadReport) {
		t.Errorf("a report from the future: %v", err)
	}
	if _, err := ParseAttachment([]byte("<html></html>"), parseNow); !errors.Is(err, ErrNoReport) {
		t.Errorf("another document: %v", err)
	}
}

func TestParseMessage(t *testing.T) {
	doc := []byte(parseDoc(parseRecord("192.0.2.1", "3")))
	body := func(kind, name string, data []byte) string {
		return "Content-Type: " + kind + "\r\nContent-Disposition: attachment; filename=\"" + name + "\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString(data) + "\r\n"
	}
	for name, raw := range map[string]string{
		"attached": "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nA report.\r\n--b\r\n" + body("application/gzip", "r.xml.gz", gzipped(t, doc)) + "--b--\r\n",
		"bare":     body("application/zip", "r.zip", zipped(t, doc)),
		"mistyped": body("application/octet-stream", "r", doc),
		"plain":    "Content-Type: text/xml\r\n\r\n" + string(doc),
	} {
		f, err := ParseMessage([]byte(raw), parseNow)
		if err != nil || len(f.Records) != 1 || f.Records[0].Row.Count != 3 {
			t.Errorf("%s: %+v %v", name, f, err)
		}
	}
	for _, raw := range []string{"Subject: hello\r\n\r\nJust mail.", "not a message", ""} {
		if _, err := ParseMessage([]byte(raw), parseNow); !errors.Is(err, ErrNoReport) {
			t.Errorf("%q: %v", raw, err)
		}
	}
}

func FuzzParseAttachment(f *testing.F) {
	doc := []byte(parseDoc(parseRecord("192.0.2.1", "1")))
	f.Add(doc)
	f.Add(gzipped(f, doc))
	f.Add(zipped(f, doc))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseAttachment(data, parseNow)
		if err != nil {
			if !errors.Is(err, ErrBadReport) && !errors.Is(err, ErrNoReport) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		if _, ok := reportDomain(r.PolicyPublished.Domain); !ok || len(r.Records) > MaxReportRecords {
			t.Fatalf("accepted %+v", r.PolicyPublished)
		}
		for _, rec := range r.Records {
			if rec.Row.Count < 1 || strings.ContainsAny(rec.Identifiers.HeaderFrom+rec.Row.SourceIP, "<>\x00\r\n") {
				t.Fatalf("accepted %+v", rec)
			}
		}
	})
}

func FuzzParseMessage(f *testing.F) {
	f.Add([]byte("Content-Type: text/xml\r\n\r\n" + parseDoc(parseRecord("192.0.2.1", "1"))))
	f.Add([]byte("Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nx\r\n--b--\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := ParseMessage(data, parseNow); err != nil && !errors.Is(err, ErrBadReport) && !errors.Is(err, ErrNoReport) {
			t.Fatalf("unexpected error %v", err)
		}
	})
}
