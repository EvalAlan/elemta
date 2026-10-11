package suppression

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"strings"
	"time"
)

// Spam complaints from feedback loops (ARF, RFC 5965).
//
// Mailbox providers that run a feedback loop send a report to a registered
// address each time one of their users presses "this is spam" on mail from
// us. Each report names the complaining recipient. Continuing to mail that
// address is the fastest way to lose the provider's trust, so a complaint
// suppresses the address the same way a hard bounce does, and outranks it.
//
// Reports are only read from mail addressed to the configured feedback
// addresses. Anyone can send a message shaped like a report, and acting on
// every one that arrives would let a stranger suppress any address they liked.

// FeedbackReport is the part of an ARF report suppression acts on.
type FeedbackReport struct {
	// FeedbackType is the report's Feedback-Type, lower-cased: "abuse",
	// "fraud", "virus", "not-spam", "auth-failure" or "other".
	FeedbackType string
	// Recipients are the addresses the original message was sent to, from
	// Original-Rcpt-To or, when the provider redacts that, the original
	// message's To header.
	Recipients []string
	// SourceIP and ReportedDomain are kept for the log.
	SourceIP       string
	ReportedDomain string
	UserAgent      string
}

// ErrNotFeedbackReport means the message is not an ARF report.
var ErrNotFeedbackReport = errors.New("not an ARF feedback report")

// IsComplaint reports whether the report is a recipient saying they do not
// want the mail. "not-spam" is the opposite, auth-failure reports are about
// DMARC alignment rather than the recipient, and "other" says too little to
// remove an address on.
func (r FeedbackReport) IsComplaint() bool {
	switch r.FeedbackType {
	case "abuse", "fraud", "virus":
		return true
	}
	return false
}

// maxReportSize bounds how much of a report is read. Real reports are a few
// kilobytes plus a copy of the original message.
const maxReportSize = 10 << 20

// ParseFeedbackReport reads an ARF report from a raw RFC 5322 message.
func ParseFeedbackReport(raw []byte) (FeedbackReport, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return FeedbackReport{}, fmt.Errorf("%w: %v", ErrNotFeedbackReport, err)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/report" ||
		!strings.EqualFold(params["report-type"], "feedback-report") || params["boundary"] == "" {
		return FeedbackReport{}, ErrNotFeedbackReport
	}

	var report FeedbackReport
	var sawReport bool
	var originalTo []string

	mr := multipart.NewReader(io.LimitReader(msg.Body, maxReportSize), params["boundary"])
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return FeedbackReport{}, fmt.Errorf("%w: %v", ErrNotFeedbackReport, err)
		}
		partType, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
		switch partType {
		case "message/feedback-report":
			fields, err := readFields(part)
			if err != nil {
				return FeedbackReport{}, fmt.Errorf("%w: feedback fields: %v", ErrNotFeedbackReport, err)
			}
			sawReport = true
			report.FeedbackType = strings.ToLower(strings.TrimSpace(fields.Get("Feedback-Type")))
			report.SourceIP = strings.TrimSpace(fields.Get("Source-IP"))
			report.ReportedDomain = strings.TrimSpace(fields.Get("Reported-Domain"))
			report.UserAgent = strings.TrimSpace(fields.Get("User-Agent"))
			for _, v := range fields.Values("Original-Rcpt-To") {
				if addr := cleanAddress(v); addr != "" {
					report.Recipients = append(report.Recipients, addr)
				}
			}
		case "message/rfc822", "text/rfc822-headers":
			if headers, err := readFields(part); err == nil {
				originalTo = addressesIn(headers.Get("To"))
			}
		}
	}
	if !sawReport {
		return FeedbackReport{}, ErrNotFeedbackReport
	}
	if len(report.Recipients) == 0 {
		report.Recipients = originalTo
	}
	return report, nil
}

// readFields reads an RFC 822 style header block, which is the format of both
// the feedback-report part and the headers of the original message.
func readFields(r io.Reader) (textproto.MIMEHeader, error) {
	tp := textproto.NewReader(bufio.NewReader(io.LimitReader(r, 1<<20)))
	h, err := tp.ReadMIMEHeader()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return h, nil
}

// cleanAddress takes an Original-Rcpt-To value, which may be bare or wrapped
// in angle brackets, and returns the address or "".
func cleanAddress(v string) string {
	v = strings.TrimSpace(v)
	if addr, err := mail.ParseAddress(v); err == nil {
		return Normalize(addr.Address)
	}
	v = Normalize(v)
	if strings.Count(v, "@") != 1 || strings.ContainsAny(v, " ,;") {
		return ""
	}
	return v
}

func addressesIn(header string) []string {
	if header == "" {
		return nil
	}
	list, err := mail.ParseAddressList(header)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, Normalize(a.Address))
	}
	return out
}

// RecordFeedbackReport suppresses the recipients named in an ARF complaint.
// A message that is not a report, or a report that is not a complaint, is
// logged and ignored; nothing here can affect delivery of the report itself.
func (r *Recorder) RecordFeedbackReport(raw []byte) {
	if r == nil || r.store == nil {
		return
	}
	report, err := ParseFeedbackReport(raw)
	if err != nil {
		r.logger.Info("Message to a feedback address is not an ARF report; nothing suppressed", "error", err)
		return
	}
	if !report.IsComplaint() {
		r.logger.Info("Feedback report is not a complaint; nothing suppressed",
			"feedback_type", report.FeedbackType, "reported_domain", report.ReportedDomain)
		return
	}
	// Counted before anything else can stop it: a report with redacted
	// recipients is still a complaint about our mail, and the complaint
	// rate is the number receivers judge a sender by.
	if r.onComplaint != nil {
		r.onComplaint(report)
	}
	if len(report.Recipients) == 0 {
		r.logger.Warn("Complaint report names no recipient (redacted by the provider?); nothing suppressed",
			"user_agent", report.UserAgent, "reported_domain", report.ReportedDomain)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reason := "spam complaint"
	if report.UserAgent != "" {
		reason += " via " + report.UserAgent
	}
	for _, addr := range report.Recipients {
		if err := r.store.Add(ctx, Entry{Address: addr, Source: SourceComplaint, Reason: reason}); err != nil {
			r.logger.Warn("Could not record a complaint", "address", addr, "error", err)
			continue
		}
		r.logger.Info("Address suppressed",
			"event_type", "suppression",
			"address", addr,
			"source", string(SourceComplaint),
			"feedback_type", report.FeedbackType,
			"reported_domain", report.ReportedDomain,
			"source_ip", report.SourceIP,
		)
	}
}
