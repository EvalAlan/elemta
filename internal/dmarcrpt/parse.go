package dmarcrpt

// The receiving side: reading aggregate reports other servers send about
// this one's domains (RFC 7489 §7.2).
//
// Anyone can mail a report address, so every byte here is hostile. Sizes are
// bounded before and after decompression, XML may not declare a DTD, and
// whatever will be stored or shown is checked or cut to length.

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset" // transfer and header charsets
	"golang.org/x/text/encoding/charmap"
)

const (
	// MaxReportCompressed bounds a report attachment as sent.
	MaxReportCompressed = 10 << 20
	// MaxReportExpanded bounds it unpacked.
	MaxReportExpanded = 20 << 20
	// MaxReportRecords bounds its rows.
	MaxReportRecords = 50000

	maxReportParts = 50
	maxReportDepth = 8
	maxReportCount = 1_000_000_000
	maxReportText  = 200
	// maxReportSpan allows for the weekly and monthly reporters.
	maxReportSpan = 32 * 24 * time.Hour
)

var (
	// ErrNoReport is a message with no aggregate report in it.
	ErrNoReport = errors.New("no DMARC aggregate report")
	// ErrBadReport is a report that is malformed or over a limit.
	ErrBadReport = errors.New("invalid DMARC aggregate report")
)

func badReport(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBadReport, fmt.Sprintf(format, args...))
}

// ParseMessage finds the report in a mail message and parses it.
func ParseMessage(raw []byte, now time.Time) (*Feedback, error) {
	entity, err := message.Read(bytes.NewReader(raw))
	if entity == nil || (err != nil && !message.IsUnknownCharset(err)) {
		return nil, ErrNoReport
	}
	parts := 0
	return findReport(entity, now, 0, &parts)
}

func findReport(e *message.Entity, now time.Time, depth int, parts *int) (*Feedback, error) {
	if depth > maxReportDepth {
		return nil, badReport("MIME parts nest too deeply")
	}
	if multi := e.MultipartReader(); multi != nil {
		for {
			*parts++
			if *parts > maxReportParts {
				return nil, badReport("too many MIME parts")
			}
			part, err := multi.NextPart()
			if errors.Is(err, io.EOF) {
				return nil, ErrNoReport
			}
			if part == nil || (err != nil && !message.IsUnknownCharset(err)) {
				return nil, ErrNoReport
			}
			f, err := findReport(part, now, depth+1, parts)
			if !errors.Is(err, ErrNoReport) {
				return f, err
			}
		}
	}
	kind, params, _ := e.Header.ContentType()
	_, disposition, _ := e.Header.ContentDisposition()
	name := strings.ToLower(disposition["filename"])
	if name == "" {
		name = strings.ToLower(params["name"])
	}
	kind = strings.ToLower(kind)
	candidate := strings.HasSuffix(name, ".xml") || strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".zip") ||
		strings.Contains(kind, "xml") || strings.Contains(kind, "gzip") || strings.Contains(kind, "zip") || kind == "application/octet-stream"
	if !candidate {
		return nil, ErrNoReport
	}
	data, err := readLimited(e.Body, MaxReportCompressed)
	if err != nil {
		return nil, err
	}
	return ParseAttachment(data, now)
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if int64(len(data)) > limit {
		return nil, badReport("larger than %d MiB", limit>>20)
	}
	if err != nil {
		return nil, badReport("unreadable attachment: %v", err)
	}
	return data, nil
}

// ParseAttachment parses a report as sent: XML, gzip, or a zip holding one
// file. The content decides which, since senders' types and names are often
// wrong.
func ParseAttachment(data []byte, now time.Time) (*Feedback, error) {
	if len(data) > MaxReportCompressed {
		return nil, badReport("larger than %d MiB", MaxReportCompressed>>20)
	}
	switch {
	case bytes.HasPrefix(data, []byte{0x1f, 0x8b}):
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, badReport("unreadable gzip: %v", err)
		}
		defer func() { _ = zr.Close() }()
		if data, err = readLimited(zr, MaxReportExpanded); err != nil {
			return nil, err
		}
	case bytes.HasPrefix(data, []byte("PK\x03\x04")):
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, badReport("unreadable zip: %v", err)
		}
		if len(zr.File) != 1 {
			return nil, badReport("a zip must hold exactly one file")
		}
		rc, err := zr.File[0].Open()
		if err != nil {
			return nil, badReport("unreadable zip: %v", err)
		}
		defer func() { _ = rc.Close() }()
		// The size the zip claims is the sender's word, so it's measured.
		if data, err = readLimited(rc, MaxReportExpanded); err != nil {
			return nil, err
		}
	}
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")))
	if !bytes.HasPrefix(trimmed, []byte("<")) {
		return nil, ErrNoReport
	}
	f, err := parseXML(trimmed)
	if err != nil {
		return nil, err
	}
	if err := f.check(now); err != nil {
		return nil, err
	}
	return f, nil
}

// parseXML reads record by record, so the row limit holds before the rows
// are all in memory.
func parseXML(data []byte) (*Feedback, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.CharsetReader = func(label string, in io.Reader) (io.Reader, error) {
		switch strings.ToLower(label) {
		case "utf-8", "utf8", "us-ascii", "ascii":
			return in, nil
		case "iso-8859-1", "latin1", "windows-1252":
			return charmap.Windows1252.NewDecoder().Reader(in), nil
		}
		return nil, fmt.Errorf("unsupported charset %q", label)
	}
	f := &Feedback{}
	depth := 0
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, badReport("XML: %v", err)
		}
		switch t := tok.(type) {
		case xml.Directive:
			return nil, badReport("a DTD or other XML directive")
		case xml.EndElement:
			depth--
		case xml.StartElement:
			if depth == 0 {
				if f.XMLName.Local != "" {
					return nil, badReport("more than one document")
				}
				if t.Name.Local != "feedback" {
					return nil, ErrNoReport
				}
				f.XMLName = t.Name
				depth++
				continue
			}
			var err error
			switch t.Name.Local {
			case "version":
				err = d.DecodeElement(&f.Version, &t)
			case "report_metadata":
				err = d.DecodeElement(&f.ReportMetadata, &t)
			case "policy_published":
				err = d.DecodeElement(&f.PolicyPublished, &t)
			case "record":
				if len(f.Records) >= MaxReportRecords {
					return nil, badReport("more than %d records", MaxReportRecords)
				}
				var r Record
				err = d.DecodeElement(&r, &t)
				f.Records = append(f.Records, r)
			default:
				err = d.Skip()
			}
			if err != nil {
				return nil, badReport("XML: %v", err)
			}
		}
	}
	if f.XMLName.Local == "" {
		return nil, ErrNoReport
	}
	return f, nil
}

func (f *Feedback) check(now time.Time) error {
	m, p := &f.ReportMetadata, &f.PolicyPublished
	m.OrgName, m.Email, m.ReportID = reportText(m.OrgName), reportText(m.Email), reportText(m.ReportID)
	m.Errors = nil
	if m.ReportID == "" {
		return badReport("no report id")
	}
	var ok bool
	if p.Domain, ok = reportDomain(p.Domain); !ok {
		return badReport("no valid policy domain")
	}
	p.P = oneOf(p.P, "", "none", "quarantine", "reject")
	p.SP = oneOf(p.SP, "", "none", "quarantine", "reject")
	if p.Pct < 0 || p.Pct > 100 {
		p.Pct = 0
	}
	begin, end := m.DateRange.Begin, m.DateRange.End
	first := time.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC).Unix() // before DMARC
	last := now.Add(2 * 24 * time.Hour).Unix()
	if begin < first || begin > last || end < begin || end-begin > int64(maxReportSpan/time.Second) {
		return badReport("implausible date range")
	}
	for i := range f.Records {
		r := &f.Records[i]
		ip, err := netip.ParseAddr(strings.TrimSpace(r.Row.SourceIP))
		if err != nil || ip.Zone() != "" {
			return badReport("record %d has no valid source address", i+1)
		}
		r.Row.SourceIP = ip.Unmap().String()
		if r.Row.Count < 1 || r.Row.Count > maxReportCount {
			return badReport("record %d has an implausible count", i+1)
		}
		e := &r.Row.PolicyEvaluated
		e.Disposition = oneOf(e.Disposition, "none", "quarantine", "reject")
		e.DKIM = oneOf(e.DKIM, "fail", "pass")
		e.SPF = oneOf(e.SPF, "fail", "pass")
		e.Reasons = nil
		// Some reporters leave header_from out; it was judged under the
		// policy domain either way.
		if strings.TrimSpace(r.Identifiers.HeaderFrom) == "" {
			r.Identifiers.HeaderFrom = p.Domain
		} else if r.Identifiers.HeaderFrom, ok = reportDomain(r.Identifiers.HeaderFrom); !ok {
			return badReport("record %d has no valid From domain", i+1)
		}
		r.Identifiers.EnvelopeFrom, _ = reportDomain(r.Identifiers.EnvelopeFrom)
		for j := range r.AuthResults.DKIM {
			a := &r.AuthResults.DKIM[j]
			a.Domain, _ = reportDomain(a.Domain)
			a.Selector, a.Result = reportText(a.Selector), enumOr(a.Result, dkimResults)
		}
		for j := range r.AuthResults.SPF {
			a := &r.AuthResults.SPF[j]
			a.Domain, _ = reportDomain(a.Domain)
			a.Scope, a.Result = reportText(a.Scope), enumOr(a.Result, spfResults)
		}
	}
	return nil
}

// oneOf returns v lowered if it's allowed, or else fallback, which is
// allowed as well.
func oneOf(v, fallback string, others ...string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	for _, o := range others {
		if v == o {
			return v
		}
	}
	return fallback
}

func reportText(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	s = strings.TrimSpace(s)
	if len(s) > maxReportText {
		s = strings.ToValidUTF8(s[:maxReportText], "")
	}
	return s
}

// reportDomain is a domain fit to store, or "" and false.
func reportDomain(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if s == "" || len(s) > 253 || !utf8.ValidString(s) {
		return "", false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, r := range label {
			if r == utf8.RuneError || r != '-' && r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsMark(r) {
				return "", false
			}
		}
	}
	return s, true
}
